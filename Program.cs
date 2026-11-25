using System;
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Text;
using Iced.Intel;
using Decoder = Iced.Intel.Decoder;

namespace ChromiumPatcher
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct SectionHeader
    {
        public fixed byte NameBytes[8];
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;

        public unsafe string Name
        {
            get
            {
                fixed (byte* ptr = NameBytes)
                {
                    int len = 0;
                    while (len < 8 && ptr[len] != 0) len++;
                    return Encoding.ASCII.GetString(ptr, len);
                }
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct RuntimeFunction
    {
        public uint BeginAddress;
        public uint EndAddress;
        public uint UnwindData;
    }

    public sealed unsafe class PeFile : IDisposable
    {
        private readonly MemoryMappedFile mmf_;
        private readonly MemoryMappedViewAccessor accessor_;
        private readonly byte* base_ptr_;
        private readonly long file_length_;
        private readonly SectionHeader[] sections_;

        public ulong ImageBase { get; }
        public SectionHeader TextSection { get; }
        public SectionHeader RDataSection { get; }
        public SectionHeader PDataSection { get; }
        public byte* BasePointer => base_ptr_;
        public long FileLength => file_length_;

        private PeFile(string file_path)
        {
            var file_info = new FileInfo(file_path);
            file_length_ = file_info.Length;

            mmf_ = MemoryMappedFile.CreateFromFile(file_path, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
            accessor_ = mmf_.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
            accessor_.SafeMemoryMappedViewHandle.AcquirePointer(ref base_ptr_);

            int e_lfanew = *(int*)(base_ptr_ + 0x3C);
            byte* nt = base_ptr_ + e_lfanew;
            ushort num_sections = *(ushort*)(nt + 6);
            ushort opt_size = *(ushort*)(nt + 0x14);
            byte* opt = nt + 0x18;

            ImageBase = *(ulong*)(opt + 0x18);
            byte* sec_ptr = opt + opt_size;

            sections_ = new SectionHeader[num_sections];
            for (int i = 0; i < num_sections; i++)
            {
                sections_[i] = *(SectionHeader*)(sec_ptr + i * sizeof(SectionHeader));
                string name = sections_[i].Name;
                if (name == ".text") TextSection = sections_[i];
                else if (name == ".rdata") RDataSection = sections_[i];
                else if (name == ".pdata") PDataSection = sections_[i];
            }
        }

        public static PeFile Open(string file_path) => new PeFile(file_path);

        public uint RvaToOffset(uint rva)
        {
            foreach (var sec in sections_)
            {
                uint size = Math.Max(sec.VirtualSize, sec.SizeOfRawData);
                if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + size)
                {
                    return (rva - sec.VirtualAddress) + sec.PointerToRawData;
                }
            }
            return 0;
        }

        public uint FindFunctionStartByPData(uint target_rva)
        {
            if (PDataSection.PointerToRawData == 0 || PDataSection.SizeOfRawData < sizeof(RuntimeFunction))
                return 0;

            int count = (int)(PDataSection.SizeOfRawData / sizeof(RuntimeFunction));
            RuntimeFunction* entries = (RuntimeFunction*)(base_ptr_ + PDataSection.PointerToRawData);

            int low = 0;
            int high = count - 1;
            while (low <= high)
            {
                int mid = low + (high - low) / 2;
                ref RuntimeFunction rf = ref entries[mid];
                if (rf.BeginAddress <= target_rva && target_rva < rf.EndAddress)
                {
                    return rf.BeginAddress;
                }
                if (target_rva < rf.BeginAddress)
                {
                    high = mid - 1;
                }
                else
                {
                    low = mid + 1;
                }
            }
            return 0;
        }

        public ReadOnlySpan<byte> GetSectionSpan(SectionHeader sec)
        {
            if (sec.PointerToRawData == 0 || sec.SizeOfRawData == 0)
                return ReadOnlySpan<byte>.Empty;
            return new ReadOnlySpan<byte>(base_ptr_ + sec.PointerToRawData, (int)sec.SizeOfRawData);
        }

        public void Dispose()
        {
            if (base_ptr_ != null)
            {
                accessor_.SafeMemoryMappedViewHandle.ReleasePointer();
            }
            if (accessor_ != null)
            {
                accessor_.Dispose();
            }
            if (mmf_ != null)
            {
                mmf_.Dispose();
            }
        }
    }

    public sealed unsafe class UnmanagedCodeReader : CodeReader
    {
        private readonly byte* ptr_;
        private readonly int length_;
        private int pos_;

        public UnmanagedCodeReader(byte* ptr, int length)
        {
            ptr_ = ptr;
            length_ = length;
            pos_ = 0;
        }

        public override int ReadByte() => pos_ < length_ ? ptr_[pos_++] : -1;
    }

    public class PatchTarget
    {
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public ulong Va { get; set; }
        public uint Rva { get; set; }
        public uint FileOffset { get; set; }
        public byte OriginalByte { get; set; }
        public byte CurrentByte { get; set; }
        public bool IsPatched => CurrentByte == 0xC3;
    }

    public class AddItemResult
    {
        public ulong Va { get; set; }
        public uint Rva { get; set; }
        public uint FileOffset { get; set; }
    }

    internal class Program
    {
        static void Main(string[] args)
        {
            PrintBanner();

            if (args.Length == 0 || args[0] == "-h" || args[0] == "--help")
            {
                PrintUsage();
                return;
            }

            string mode = "--analyze";
            string dll_path = "";

            if (args.Length == 1)
            {
                dll_path = args[0];
            }
            else
            {
                mode = args[0].ToLowerInvariant();
                dll_path = args[1];
            }

            if (!File.Exists(dll_path))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[错误] 文件不存在: {dll_path}");
                Console.ResetColor();
                return;
            }

            try
            {
                switch (mode)
                {
                    case "--analyze":
                    case "-a":
                        RunAnalyze(dll_path);
                        break;
                    case "--patch":
                    case "-p":
                        RunPatch(dll_path);
                        break;
                    case "--unpatch":
                    case "-u":
                        RunUnpatch(dll_path);
                        break;
                    default:
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[错误] 未知参数选项: {mode}");
                        Console.ResetColor();
                        PrintUsage();
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[异常] 执行出错: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
                Console.ResetColor();
            }
        }

        static void PrintBanner()
        {
            Console.WriteLine("==================================================================");
            Console.WriteLine("               Chromium / Chromium Mod Analyzer & Patcher           ");
            Console.WriteLine("==================================================================");
        }

        static void PrintUsage()
        {
            Console.WriteLine("用法:");
            Console.WriteLine("  ChromiumPatcher [--analyze|-a] <chrome.dll 路径>   分析目标地址与补丁状态 (默认)");
            Console.WriteLine("  ChromiumPatcher --patch|-p    <chrome.dll 路径>   一键执行补丁 (自动备份 .bak)");
            Console.WriteLine("  ChromiumPatcher --unpatch|-u  <chrome.dll 路径>   还原补丁为原始字节");
            Console.WriteLine();
            Console.WriteLine("功能清单:");
            Console.WriteLine("  1. 移除 90 天历史记录限制 (ExpireHistoryBackend::StartExpiringOldStuff)");
            Console.WriteLine("  2. 移除搜索记录存储 (URLDatabase::SetKeywordSearchTermsForURL -> ret)");
            Console.WriteLine("  3. 定位 SimpleMenuModel::AddItem 函数地址 (十进制 / 十六进制)");
            Console.WriteLine("==================================================================");
        }

        static unsafe (PatchTarget target_history, PatchTarget target_keyword, AddItemResult add_item) ScanTargets(PeFile pe)
        {
            var sw = Stopwatch.StartNew();
            Console.WriteLine($"[1/3] 解析 PE 结构完成 (ImageBase: 0x{pe.ImageBase:X}, .text 大小: {pe.TextSection.SizeOfRawData / 1024 / 1024} MB)");

            var text_span = pe.GetSectionSpan(pe.TextSection);
            var rdata_span = pe.GetSectionSpan(pe.RDataSection);

            PatchTarget target_history = null;
            PatchTarget target_keyword = null;
            AddItemResult add_item = null;

            byte[] pattern_90d = new byte[] { 0x48, 0xBA, 0x00, 0xC0, 0xB7, 0x7D, 0x12, 0x07, 0x00, 0x00 };
            int off_90d = text_span.IndexOf(pattern_90d);
            if (off_90d >= 0)
            {
                uint mov_rva = (uint)(pe.TextSection.VirtualAddress + off_90d);
                ulong mov_va = pe.ImageBase + mov_rva;
                uint mov_foa = pe.TextSection.PointerToRawData + (uint)off_90d;

                var reader = new UnmanagedCodeReader(pe.BasePointer + mov_foa, 64);
                var decoder = Decoder.Create(64, reader);
                decoder.IP = mov_va;

                ulong call_target_va = 0;
                while (decoder.IP < mov_va + 40)
                {
                    decoder.Decode(out var ins);
                    if (ins.Mnemonic == Mnemonic.Call && ins.Op0Kind == OpKind.NearBranch64)
                    {
                        call_target_va = ins.NearBranchTarget;
                        break;
                    }
                }

                if (call_target_va != 0)
                {
                    uint func_rva = (uint)(call_target_va - pe.ImageBase);
                    uint pdata_func_rva = pe.FindFunctionStartByPData(func_rva);
                    if (pdata_func_rva != 0) func_rva = pdata_func_rva;

                    uint func_foa = pe.RvaToOffset(func_rva);
                    byte cur_byte = *(pe.BasePointer + func_foa);

                    target_history = new PatchTarget
                    {
                        Name = "ExpireHistoryBackend::StartExpiringOldStuff",
                        Description = "移除90天历史记录自动过期",
                        Va = pe.ImageBase + func_rva,
                        Rva = func_rva,
                        FileOffset = func_foa,
                        OriginalByte = 0x41,
                        CurrentByte = cur_byte
                    };
                }
            }

            byte[] str_keyword_bytes = Encoding.ASCII.GetBytes("INSERT INTO keyword_search_terms (keyword_id,");
            int off_keyword_str = rdata_span.IndexOf(str_keyword_bytes);
            ulong str_keyword_va = (off_keyword_str >= 0) ? (pe.ImageBase + pe.RDataSection.VirtualAddress + (uint)off_keyword_str) : 0;

            byte[] str_compose_bytes = Encoding.ASCII.GetBytes("Compose.ContextMenu.ItemSeen");
            int off_compose_str = rdata_span.IndexOf(str_compose_bytes);
            ulong str_compose_va = (off_compose_str >= 0) ? (pe.ImageBase + pe.RDataSection.VirtualAddress + (uint)off_compose_str) : 0;

            Console.WriteLine("[2/3] 扫描 .text 节交叉引用...");
            ulong xref_keyword = 0;
            ulong xref_compose = 0;

            var text_reader = new UnmanagedCodeReader(pe.BasePointer + pe.TextSection.PointerToRawData, (int)pe.TextSection.SizeOfRawData);
            var text_decoder = Decoder.Create(64, text_reader);
            text_decoder.IP = pe.ImageBase + pe.TextSection.VirtualAddress;
            ulong text_end = text_decoder.IP + pe.TextSection.SizeOfRawData;

            Instruction instr;
            while (text_decoder.IP < text_end)
            {
                text_decoder.Decode(out instr);
                if (str_keyword_va != 0 && xref_keyword == 0 && instr.MemoryDisplacement64 == str_keyword_va)
                {
                    xref_keyword = instr.IP;
                }
                if (str_compose_va != 0 && xref_compose == 0 && instr.MemoryDisplacement64 == str_compose_va)
                {
                    xref_compose = instr.IP;
                }
                if ((str_keyword_va == 0 || xref_keyword != 0) && (str_compose_va == 0 || xref_compose != 0))
                    break;
            }

            if (xref_keyword != 0)
            {
                uint xref_rva = (uint)(xref_keyword - pe.ImageBase);
                uint func_rva = pe.FindFunctionStartByPData(xref_rva);
                if (func_rva != 0)
                {
                    uint func_foa = pe.RvaToOffset(func_rva);
                    byte cur_byte = *(pe.BasePointer + func_foa);

                    target_keyword = new PatchTarget
                    {
                        Name = "URLDatabase::SetKeywordSearchTermsForURL",
                        Description = "移除搜索词数据库写入 (INSERT INTO keyword_search_terms)",
                        Va = pe.ImageBase + func_rva,
                        Rva = func_rva,
                        FileOffset = func_foa,
                        OriginalByte = 0x41,
                        CurrentByte = cur_byte
                    };
                }
            }

            if (xref_compose != 0)
            {
                uint xref_foa = pe.RvaToOffset((uint)(xref_compose - pe.ImageBase));
                var compose_reader = new UnmanagedCodeReader(pe.BasePointer + xref_foa, 128);
                var compose_dec = Decoder.Create(64, compose_reader);
                compose_dec.IP = xref_compose;

                int call_idx = 0;
                ulong add_item_with_string_id_va = 0;

                while (compose_dec.IP < xref_compose + 100)
                {
                    compose_dec.Decode(out var ins);
                    if (ins.Mnemonic == Mnemonic.Call && ins.Op0Kind == OpKind.NearBranch64)
                    {
                        call_idx++;
                        if (call_idx == 2)
                        {
                            add_item_with_string_id_va = ins.NearBranchTarget;
                            break;
                        }
                    }
                }

                if (add_item_with_string_id_va != 0)
                {
                    uint fn_rva = (uint)(add_item_with_string_id_va - pe.ImageBase);
                    uint fn_foa = pe.RvaToOffset(fn_rva);

                    var fn_reader = new UnmanagedCodeReader(pe.BasePointer + fn_foa, 256);
                    var fn_dec = Decoder.Create(64, fn_reader);
                    fn_dec.IP = add_item_with_string_id_va;

                    Register saved_this_reg = Register.None;
                    for (int i = 0; i < 15; i++)
                    {
                        fn_dec.Decode(out var ins);
                        if (ins.Mnemonic == Mnemonic.Mov && ins.Op1Register == Register.RCX && ins.Op0Kind == OpKind.Register)
                        {
                            saved_this_reg = ins.Op0Register;
                            break;
                        }
                    }

                    if (saved_this_reg != Register.None)
                    {
                        fn_reader = new UnmanagedCodeReader(pe.BasePointer + fn_foa, 512);
                        fn_dec = Decoder.Create(64, fn_reader);
                        fn_dec.IP = add_item_with_string_id_va;

                        bool rcx_is_this = false;
                        ulong add_item_va = 0;

                        while (true)
                        {
                            fn_dec.Decode(out var ins);
                            if (ins.Mnemonic == Mnemonic.Ret)
                                break;

                            if (ins.Mnemonic == Mnemonic.Mov && ins.Op0Register == Register.RCX && ins.Op1Register == saved_this_reg)
                            {
                                rcx_is_this = true;
                            }
                            else if ((ins.Mnemonic == Mnemonic.Mov || ins.Mnemonic == Mnemonic.Lea || ins.Mnemonic == Mnemonic.Xor) && ins.Op0Register == Register.RCX)
                            {
                                rcx_is_this = false;
                            }

                            if (ins.Mnemonic == Mnemonic.Call && ins.Op0Kind == OpKind.NearBranch64)
                            {
                                if (rcx_is_this)
                                {
                                    add_item_va = ins.NearBranchTarget;
                                    break;
                                }
                                rcx_is_this = false;
                            }
                        }

                        if (add_item_va != 0)
                        {
                            uint item_rva = (uint)(add_item_va - pe.ImageBase);
                            uint item_foa = pe.RvaToOffset(item_rva);
                            add_item = new AddItemResult
                            {
                                Va = add_item_va,
                                Rva = item_rva,
                                FileOffset = item_foa
                            };
                        }
                    }
                }
            }

            Console.WriteLine($"[3/3] 扫描分析完成 (耗时: {sw.ElapsedMilliseconds} ms)\n");
            return (target_history, target_keyword, add_item);
        }

        static void RunAnalyze(string dll_path)
        {
            PatchTarget target_history;
            PatchTarget target_keyword;
            AddItemResult add_item;

            using (var pe = PeFile.Open(dll_path))
            {
                (target_history, target_keyword, add_item) = ScanTargets(pe);
            }

            Console.WriteLine("======================= 目标分析结果 =======================");

            PrintPatchTargetInfo(1, target_history);
            PrintPatchTargetInfo(2, target_keyword);

            Console.WriteLine("------------------------------------------------------------------");
            Console.WriteLine("[Target 3: 定位 SimpleMenuModel::AddItem 函数地址]");
            if (add_item != null)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  相对虚拟地址 (RVA):");
                Console.WriteLine($"    十六进制 (Hex):     0x{add_item.Rva:X}");
                Console.WriteLine($"    十进制   (Decimal): {add_item.Rva}");
                Console.WriteLine($"  文件偏移 (FileOffset / FOA):");
                Console.WriteLine($"    十六进制 (Hex):     0x{add_item.FileOffset:X}");
                Console.WriteLine($"    十进制   (Decimal): {add_item.FileOffset}");
                Console.WriteLine($"  虚拟内存地址 (VA):    0x{add_item.Va:X}");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  未定位到 SimpleMenuModel::AddItem 函数！");
                Console.ResetColor();
            }
            Console.WriteLine("==================================================================");
        }

        static void PrintPatchTargetInfo(int index, PatchTarget target)
        {
            Console.WriteLine("------------------------------------------------------------------");
            if (target == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[Target {index}] 未找到目标函数！");
                Console.ResetColor();
                return;
            }

            Console.WriteLine($"[Target {index}: {target.Name}]");
            Console.WriteLine($"  说明:        {target.Description}");
            Console.WriteLine($"  虚拟地址:    VA=0x{target.Va:X}, RVA=0x{target.Rva:X}");
            Console.WriteLine($"  文件偏移:    FileOffset=0x{target.FileOffset:X}");
            Console.Write($"  补丁状态:    ");
            if (target.IsPatched)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"已打补丁 (当前字节: 0x{target.CurrentByte:X2} [ret])");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"未打补丁 (原始字节: 0x{target.CurrentByte:X2})");
            }
            Console.ResetColor();
        }

        static void RunPatch(string dll_path)
        {
            PatchTarget t1;
            PatchTarget t2;
            AddItemResult item;

            using (var pe = PeFile.Open(dll_path))
            {
                (t1, t2, item) = ScanTargets(pe);
            }

            if (t1 == null && t2 == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[错误] 未能找到任何补丁目标，补丁终止！");
                Console.ResetColor();
                return;
            }

            string bak_path = dll_path + ".bak";
            if (!File.Exists(bak_path))
            {
                Console.WriteLine($"[备份] 正在创建备份文件 -> {bak_path}");
                File.Copy(dll_path, bak_path, false);
                Console.WriteLine("[备份] 备份完成。");
            }
            else
            {
                Console.WriteLine($"[备份] 备份文件已存在，保留现有备份 -> {bak_path}");
            }

            using (var fs = new FileStream(dll_path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
            using (var writer = new BinaryWriter(fs))
            {
                Console.WriteLine("\n======================= 执行补丁写入 =======================");

                ApplySinglePatch(fs, writer, 1, t1, 0xC3);
                ApplySinglePatch(fs, writer, 2, t2, 0xC3);

                fs.Flush();
            }

            Console.WriteLine("==================================================================");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("全部补丁处理完毕！");
            Console.ResetColor();

            if (item != null)
            {
                Console.WriteLine("\n[附加信息] SimpleMenuModel::AddItem 函数地址:");
                Console.WriteLine($"  RVA: 0x{item.Rva:X} ({item.Rva})");
                Console.WriteLine($"  FOA: 0x{item.FileOffset:X} ({item.FileOffset})");
            }
        }

        static void RunUnpatch(string dll_path)
        {
            PatchTarget t1;
            PatchTarget t2;
            AddItemResult item;

            using (var pe = PeFile.Open(dll_path))
            {
                (t1, t2, item) = ScanTargets(pe);
            }

            using (var fs = new FileStream(dll_path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
            using (var writer = new BinaryWriter(fs))
            {
                Console.WriteLine("\n======================= 执行补丁还原 =======================");

                ApplySingleUnpatch(fs, writer, 1, t1);
                ApplySingleUnpatch(fs, writer, 2, t2);

                fs.Flush();
            }

            Console.WriteLine("==================================================================");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("还原处理完毕！");
            Console.ResetColor();
        }

        static void ApplySinglePatch(FileStream fs, BinaryWriter writer, int index, PatchTarget target, byte patch_byte)
        {
            if (target == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[Target {index}] 未找到目标，跳过。");
                Console.ResetColor();
                return;
            }

            if (target.IsPatched)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[Target {index}: {target.Name}] 已经处于补丁状态 (0x{target.CurrentByte:X2})，无需修改。");
                Console.ResetColor();
                return;
            }

            fs.Seek(target.FileOffset, SeekOrigin.Begin);
            writer.Write(patch_byte);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[Target {index}: {target.Name}] 补丁成功！");
            Console.WriteLine($"  偏移: 0x{target.FileOffset:X} | 字节修改: 0x{target.CurrentByte:X2} -> 0x{patch_byte:X2} (ret)");
            Console.ResetColor();
        }

        static void ApplySingleUnpatch(FileStream fs, BinaryWriter writer, int index, PatchTarget target)
        {
            if (target == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[Target {index}] 未找到目标，跳过。");
                Console.ResetColor();
                return;
            }

            if (!target.IsPatched)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"[Target {index}: {target.Name}] 当前已是原始状态 (0x{target.CurrentByte:X2})，无需还原。");
                Console.ResetColor();
                return;
            }

            fs.Seek(target.FileOffset, SeekOrigin.Begin);
            writer.Write(target.OriginalByte);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[Target {index}: {target.Name}] 还原成功！");
            Console.WriteLine($"  偏移: 0x{target.FileOffset:X} | 字节恢复: 0x{target.CurrentByte:X2} -> 0x{target.OriginalByte:X2}");
            Console.ResetColor();
        }
    }
}