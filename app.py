import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import struct
import datetime
import os

def decode_fat_time(date_bytes, time_bytes):
    """
    Decodes MS-DOS 16-bit date and time fields into a standard Python datetime object.
    
    Date format (16-bit):
    Bits 9-15: Year (0-127, relative to 1980)
    Bits 5-8:  Month (1-12)
    Bits 0-4:  Day (1-31)
    
    Time format (16-bit):
    Bits 11-15: Hour (0-23)
    Bits 5-10:  Minute (0-59)
    Bits 0-4:   Second/2 (0-29, need to multiply by 2 for actual seconds)
    """
    date_val = int.from_bytes(date_bytes, 'little')
    time_val = int.from_bytes(time_bytes, 'little')
    
    # If genuinely 0x00 across timestamp bytes, output baseline epoch (1980-01-01 00:00:00)
    if date_val == 0 and time_val == 0:
        return datetime.datetime(1980, 1, 1, 0, 0, 0)

    year = ((date_val >> 9) & 0x7F) + 1980
    month = (date_val >> 5) & 0x0F
    day = date_val & 0x1F
    
    hour = (time_val >> 11) & 0x1F
    minute = (time_val >> 5) & 0x3F
    second = (time_val & 0x1F) * 2
    
    # Validation clamp for potential corruption or edge cases
    month = max(1, min(month, 12))
    day = max(1, min(day, 31))
    
    try:
        return datetime.datetime(year, month, day, hour, minute, second)
    except ValueError:
        return datetime.datetime(1980, 1, 1, 0, 0, 0)

class ForgeryDetectorGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Temporal Forgery Detector - Phase 1")
        self.geometry("1000x600")
        
        # State variables
        self.file_path = None
        self.root_dir_offset = 0
        self.entries = []
        
        self._build_ui()
        
    def _build_ui(self):
        # -----------------------------
        # Top Panel (Controls)
        # -----------------------------
        top_frame = ttk.Frame(self, padding="10")
        top_frame.pack(side=tk.TOP, fill=tk.X)
        
        btn_select = ttk.Button(top_frame, text="Select FAT12 Image", command=self.load_image)
        btn_select.pack(side=tk.LEFT, padx=5)
        
        self.lbl_file = ttk.Label(top_frame, text="No file selected")
        self.lbl_file.pack(side=tk.LEFT, padx=15)
        
        self.lbl_offset = ttk.Label(top_frame, text="Calculated Root Dir Offset: N/A", font=("TkDefaultFont", 9, "bold"))
        self.lbl_offset.pack(side=tk.RIGHT, padx=5)
        
        # -----------------------------
        # Bottom Panel (Legend & Swatches)
        # -----------------------------
        swatches_frame = tk.Frame(self)
        swatches_frame.pack(side=tk.BOTTOM, pady=(0, 5))
        
        lbl_type_legend = ttk.Label(
            self,
            text="Type Legend: R = Read-Only | H = Hidden | S = System | V = Volume | D = Directory | A = Archive",
            font=("TkDefaultFont", 9, "italic")
        )
        lbl_type_legend.pack(side=tk.BOTTOM, pady=(5, 3))
        
        # Color Key Swatches
        tk.Label(swatches_frame, text="Color Key:", font=("TkDefaultFont", 9, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        
        swatches_data = [
            ("#ffcdd2", "Temporal Forgery / Conflict"),
            ("#fff9c4", "Benign OS Quirk (≤ 5s)"),
            ("#e3f2fd", "Volume Entry"),
            ("#e0e0e0", "Deleted / Inactive Slot")
        ]
        
        for bg_color, desc in swatches_data:
            swatch = tk.Canvas(
                swatches_frame,
                width=16,
                height=12,
                bg=bg_color,
                highlightthickness=1,
                highlightbackground="#757575"
            )
            swatch.pack(side=tk.LEFT, padx=(4, 4))
            
            lbl_desc = tk.Label(swatches_frame, text=desc, font=("TkDefaultFont", 9))
            lbl_desc.pack(side=tk.LEFT, padx=(0, 10))
        
        # -----------------------------
        # Main Panel (Split View)
        # -----------------------------
        # We use a PanedWindow to allow the user to resize the left/right tables dynamically
        main_pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=5) ###################################################################################
        
        # Left Frame: Physical Timeline
        left_frame = ttk.Frame(main_pane)
        main_pane.add(left_frame, weight=1)
        
        ttk.Label(left_frame, text="Physical Timeline (Raw Write Order)", font=("TkDefaultFont", 10, "bold")).pack(pady=5)
        
        # Setup Left Treeview
        columns = ("Index", "Hex Offset", "File Name", "Type", "Date/Time")
        self.tree_physical = ttk.Treeview(left_frame, columns=columns, show="headings")
        self._setup_treeview(self.tree_physical, columns)
        
        # Add scrollbar to Left Treeview
        scroll_phys = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.tree_physical.yview)
        self.tree_physical.configure(yscroll=scroll_phys.set)
        scroll_phys.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree_physical.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Right Frame: Logical Timeline
        right_frame = ttk.Frame(main_pane)
        main_pane.add(right_frame, weight=1)
        
        ttk.Label(right_frame, text="Logical Timeline (Metadata Order)", font=("TkDefaultFont", 10, "bold")).pack(pady=5)
        
        # Setup Right Treeview
        self.tree_logical = ttk.Treeview(right_frame, columns=columns, show="headings")
        self._setup_treeview(self.tree_logical, columns)
        
        # Add scrollbar to Right Treeview
        scroll_log = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=self.tree_logical.yview)
        self.tree_logical.configure(yscroll=scroll_log.set)
        scroll_log.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree_logical.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def _setup_treeview(self, tree, columns):
        """Helper to configure Treeview column headers and widths."""
        for col in columns:
            tree.heading(col, text=col)
            # Make columns a bit narrower except File Name and Date/Time
            if col in ["Index", "Hex Offset"]:
                tree.column(col, width=80, anchor=tk.CENTER)
            elif col == "Type":
                tree.column(col, width=70, anchor=tk.CENTER)
            else:
                tree.column(col, width=180, anchor=tk.W)

        # Configure row highlighting tags
        tree.tag_configure('volume', background='#e3f2fd')
        tree.tag_configure('conflict', background='#ffcdd2')
        tree.tag_configure('quirk', background='#fff9c4')
        tree.tag_configure('deleted', background='#e0e0e0', foreground='gray')

    def load_image(self):
        """Prompt user to select a VHD file and trigger parsing."""
        file_path = filedialog.askopenfilename(
            title="Select FAT12 Image",
            filetypes=(("VHD Files", "*.vhd"), ("All Files", "*.*"))
        )
        if not file_path:
            return
            
        self.file_path = file_path
        self.lbl_file.config(text=f"File: {os.path.basename(file_path)}")
        
        try:
            self.parse_fat12()
            self.populate_tables()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse image:\n{str(e)}")

    def parse_fat12(self):
        """
        Core logic to parse the FAT12 image dynamically.
        1. Check MBR for the first partition offset.
        2. Seek to partition and read FAT12 BPB fields.
        3. Calculate Root Directory Offset.
        4. Seek to Root Dir Offset and extract file operations sequentially.
        """
        self.entries = []
        
        with open(self.file_path, "rb") as f:
            # 1. Read Sector 0 (MBR)
            sector_0 = f.read(512)
            if len(sector_0) < 512:
                raise ValueError("File is smaller than a single sector.")
                
            # Read first partition entry LBA at offset 0x01BE + 8
            lba_start = struct.unpack_from("<I", sector_0, 0x01BE + 8)[0]
            partition_offset = lba_start * 512
            
            # Seek to the partition sector
            f.seek(partition_offset)
            
            # Now read the FAT12 Boot Sector (BPB)
            boot_sector = f.read(512)
            if len(boot_sector) < 512:
                raise ValueError("Partition is missing or invalid.")
                
            # Unpack BIOS Parameter Block (BPB) to dynamically calculate Root Dir Offset
            # Bytes_per_Sector: Offset 11, length 2 (little endian)
            bytes_per_sector = struct.unpack_from("<H", boot_sector, 11)[0]
            # Reserved_Sectors: Offset 14, length 2 (little endian)
            reserved_sectors = struct.unpack_from("<H", boot_sector, 14)[0]
            # Number_of_FATs: Offset 16, length 1
            number_of_fats = boot_sector[16]
            # Sectors_per_FAT: Offset 22, length 2 (little endian)
            sectors_per_fat = struct.unpack_from("<H", boot_sector, 22)[0]
            
            if bytes_per_sector == 0:
                # Fallback for invalid BPB just in case, typically 512
                bytes_per_sector = 512
                
            # 2. Calculate Absolute Root Directory Offset
            # The root dir offset is calculated from the start of the partition
            relative_root_dir_offset = (reserved_sectors + (number_of_fats * sectors_per_fat)) * bytes_per_sector
            self.root_dir_offset = partition_offset + relative_root_dir_offset
            
            self.lbl_offset.config(text=f"Calculated Root Dir Offset: {hex(self.root_dir_offset)}")
            
            # 3. Seek to Root Directory and extract data
            f.seek(self.root_dir_offset)
            
            physical_index = 0
            while True:
                current_offset = f.tell()
                entry = f.read(32)
                
                # Check for EOF or short reads
                if not entry or len(entry) < 32:
                    break
                    
                # Byte 0 = 0x00 indicates end of directory
                if entry[0] == 0x00:
                    break
                    
                # Ignore Long File Name (LFN) attributes (0x0F)
                if entry[11] == 0x0F:
                    # We might skip it or increment physical index, but LFNs aren't regular files.
                    # For a simple parser, we skip LFN chunks to focus on the 8.3 standard entry.
                    # However, strictly they take up space, so we increment index and continue.
                    physical_index += 1
                    continue
                    
                # Parse File Name (Bytes 0-10)
                # Handle 0xE5 correctly so it doesn't break decode
                raw_name = entry[0:11]
                if raw_name[0] == 0xE5:
                    # Substitute 0xE5 with an underscore or similar for display
                    file_name = "_" + raw_name[1:].decode("ascii", errors="replace").strip()
                else:
                    file_name = raw_name.decode("ascii", errors="replace").strip()
                
                # Parse FAT12 Attribute byte at offset 0x0B (Byte 11) using bitwise AND operations
                attr = entry[11]
                type_flags = []
                if attr & 0x01:
                    type_flags.append("R")
                if attr & 0x02:
                    type_flags.append("H")
                if attr & 0x04:
                    type_flags.append("S")
                if attr & 0x08:
                    type_flags.append("V")
                if attr & 0x10:
                    type_flags.append("D")
                if attr & 0x20:
                    type_flags.append("A")
                entry_type = "".join(type_flags)
                
                # Strictly track Creation Time (Bytes 0x0E through 0x11)
                # Byte offsets 0x0E-0x0F (14-15) = Creation Time, 0x10-0x11 (16-17) = Creation Date
                crt_time = entry[14:16]
                crt_date = entry[16:18]
                
                # Volume Label fallback: if Type contains 'V' and Creation Time/Date bytes (0x0E-0x11) are empty (0x00),
                # fall back to reading Last Write Time and Date bytes (0x16-0x19: time at 22:24, date at 24:26)
                if 'V' in entry_type and entry[14:18] == b'\x00\x00\x00\x00':
                    wrt_time = entry[22:24]
                    wrt_date = entry[24:26]
                    crt_dt = decode_fat_time(wrt_date, wrt_time)
                else:
                    crt_dt = decode_fat_time(crt_date, crt_time)
                
                # Format Creation Date/Time for display
                creation_dt_str = crt_dt.strftime("%Y-%m-%d %H:%M:%S")
                
                # Store extracted data
                self.entries.append({
                    "index": physical_index,
                    "hex_offset": hex(current_offset),
                    "file_name": file_name,
                    "type": entry_type,
                    "is_deleted": entry[0] == 0xE5,
                    "creation_dt": creation_dt_str,
                    "_raw_dt": crt_dt # Strictly Creation Time for sorting and conflict detection
                })
                
                physical_index += 1

    def populate_tables(self):
        """Clears existing treeview data and populates both tables."""
        # Clear existing data
        for row in self.tree_physical.get_children():
            self.tree_physical.delete(row)
        for row in self.tree_logical.get_children():
            self.tree_logical.delete(row)
            
        # Determine targeted conflicts by comparing each physical entry against its predecessor using Creation Time
        # Strict chronological sorting based purely and strictly on the Date/Time string
        logical_sorted = sorted(self.entries, key=lambda x: x["creation_dt"])
        
        red_conflicts = set()
        yellow_conflicts = set()
        for i in range(1, len(self.entries)):
            if 'V' in self.entries[i].get("type", ""):
                continue
            prev_entry = self.entries[i - 1]
            prev_dt = prev_entry["_raw_dt"]
            curr_dt = self.entries[i]["_raw_dt"]
            if prev_dt is not None and curr_dt is not None:
                if curr_dt < prev_dt:
                    diff_seconds = (prev_dt - curr_dt).total_seconds()
                    if diff_seconds > 5:
                        red_conflicts.add(self.entries[i]["index"])
                    else:
                        yellow_conflicts.add(self.entries[i]["index"])
                
        # 1. Populate Physical Timeline (Raw Write Order)
        for e in self.entries:
            tags = ()
            if 'V' in e.get("type", ""):
                tags = ('volume',)
            elif e["index"] in red_conflicts:
                tags = ('conflict',)
            elif e["index"] in yellow_conflicts:
                tags = ('quirk',)
            elif e.get("is_deleted", False):
                tags = ('deleted',)
                
            self.tree_physical.insert("", tk.END, values=(
                e["index"], e["hex_offset"], e["file_name"], e["type"], e["creation_dt"]
            ), tags=tags)
            
        # 2. Populate Logical Timeline (Metadata Order - Chronological)
        for e in logical_sorted:
            tags = ()
            if 'V' in e.get("type", ""):
                tags = ('volume',)
            elif e["index"] in red_conflicts:
                tags = ('conflict',)
            elif e["index"] in yellow_conflicts:
                tags = ('quirk',)
            elif e.get("is_deleted", False):
                tags = ('deleted',)
                
            self.tree_logical.insert("", tk.END, values=(
                e["index"], e["hex_offset"], e["file_name"], e["type"], e["creation_dt"]
            ), tags=tags)


if __name__ == "__main__":
    app = ForgeryDetectorGUI()
    app.mainloop()
