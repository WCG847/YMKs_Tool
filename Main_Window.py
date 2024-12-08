

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import logging
from Decoder.AnimChecker import CEKeyCheck
from Decoder.YMKs import YMKs
from Decoder.KeyframeParser import KeyframeParser, Keyframe  # New import
import struct
import threading

from Decoder.AnimGetter import CEKey

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ymks_tool.log"),
        logging.StreamHandler()
    ]
)

class YMKsTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("YMKs Tool")
        self.geometry("900x700")

        # Variables
        self.file_path = tk.StringVar()

        # GUI Components
        self.create_menu()
        self.create_file_selector()
        self.create_toc_view()
        self.create_result_log()
        self.create_action_buttons()

    def create_menu(self):
        """Create the menu bar."""
        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)

        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Open File", command=self.browse_file)
        file_menu.add_command(label="Exit", command=self.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

    def create_file_selector(self):
        """Create file selector components."""
        frame = tk.Frame(self)
        frame.pack(pady=10, fill="x")

        tk.Label(frame, text="YMKs Archive File:").pack(side="left", padx=5)
        tk.Entry(frame, textvariable=self.file_path, width=50).pack(side="left", padx=5)
        tk.Button(frame, text="Browse", command=self.browse_file).pack(side="left", padx=5)

    def create_toc_view(self):
        """Create Treeview to display TOC."""
        frame = tk.Frame(self)
        frame.pack(pady=10, fill="both", expand=True)

        tk.Label(frame, text="Table of Contents (TOC):").pack(anchor="w", padx=5)

        # Create Treeview with scrollbar
        self.toc_tree = ttk.Treeview(frame, columns=("Offset", "Size", "Keyframes"), show="tree headings")
        self.toc_tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.toc_tree.yview)
        self.toc_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        # Bind the expand event
        self.toc_tree.bind("<<TreeviewOpen>>", self.on_treeview_expand)

    def on_treeview_expand(self, event):
        """Handle the event when a Treeview node is expanded."""
        node = self.toc_tree.focus()
        node_text = self.toc_tree.item(node, "text")

        # Check if the node is a keyframe placeholder
        if node_text.startswith("Keyframe") and not self.toc_tree.item(node, "values")[0]:
            # Fetch actual keyframe data
            parent_node = self.toc_tree.parent(node)
            parent_values = self.toc_tree.item(parent_node, "values")
        
            # Ensure valid parent values
            if len(parent_values) < 3:
                self.display_error("Parent node doesn't have the expected number of values.")
                return
        
            try:
                animation_offset = int(parent_values[0], 16)
            except ValueError:
                self.display_error(f"Invalid animation offset: {parent_values[0]}")
                return

            num_keyframes = int(parent_values[2])

            # Determine which keyframe to load
            keyframe_index = int(node_text.split(" ")[1]) - 1

            # Define search_params based on your implementation
            sector_offset = 0  # Example value
            anim_offset = animation_offset
            keyframes_count = num_keyframes
            search_params = (sector_offset, anim_offset, keyframes_count)

            # Define asset_index and data_index based on your implementation
            asset_index = 0
            data_index = keyframe_index

            # Call get_data to retrieve keyframe data
            extracted_data = CEKey.get_data(
                file_path=self.file_path.get(),
                search_params=search_params,
                asset_index=asset_index,
                data_index=data_index
            )

            if not extracted_data:
                self.display_error("Failed to retrieve keyframe data.")
                return

            extracted_value, byte_buffer = extracted_data

            # Update the keyframe node with actual data
            self.toc_tree.item(node, values=(f"{extracted_value}", f"{len(byte_buffer)} bytes", "-"))
            # Optionally, display byte data as a tooltip or in another GUI element


    def create_result_log(self):
        """Create result log display."""
        frame = tk.Frame(self)
        frame.pack(pady=10, fill="x")

        tk.Label(frame, text="Result Log:").pack(anchor="w", padx=5)

        self.result_text = tk.Text(frame, height=10, wrap="word")
        self.result_text.pack(fill="x", padx=5, pady=5)
        
        # Configure tags for styling
        self.result_text.tag_configure("error", foreground="red")

    def create_action_buttons(self):
        """Create buttons for user actions."""
        frame = tk.Frame(self)
        frame.pack(pady=10)

        tk.Button(frame, text="Parse Archive", command=self.parse_archive).pack(side="left", padx=10)
        tk.Button(frame, text="Extract Animation", command=self.extract_animation).pack(side="left", padx=10)
        tk.Button(frame, text="Analyze Animation", command=self.analyze_animation).pack(side="left", padx=10)
        tk.Button(frame, text="Analyze Exported .anim", command=self.analyze_exported_anim).pack(side="left", padx=10)


    def browse_file(self):
        """Open a file dialog to select the YMKs archive."""
        file_path = filedialog.askopenfilename(filetypes=[("YMKs Archives", "*.ymk"), ("All files", "*.*")])
        if file_path:
            self.file_path.set(file_path)

    def parse_archive(self):
        """Parse the YMKs archive and populate the TOC Treeview."""
        file_path = self.file_path.get()
        if not file_path:
            self.display_error("Please select a file to parse.")
            return

        try:
            toc_data = YMKs.build_toc(file_path)  # Use the new build_toc method
            logging.debug(f"TOC Data: {toc_data}")  # Log the entire TOC data
            if toc_data:
                self.toc_tree.delete(*self.toc_tree.get_children())  # Clear previous TOC
                self.populate_toc(toc_data)
                self.display_result("Archive parsed successfully.")
            else:
                self.display_error("Failed to parse the archive.")
        except Exception as e:
            logging.exception("Error parsing archive")
            self.display_error(f"Error parsing archive: {e}")

    def populate_toc(self, toc_data):
        """Populate the Treeview with TOC data in a hierarchical folder-like structure."""
        try:
            # Clear existing data
            self.toc_tree.delete(*self.toc_tree.get_children())

            # Define Treeview columns
            self.toc_tree["columns"] = ("Offset", "Size", "Keyframes")
            self.toc_tree.heading("#0", text="Entry Name", anchor="w")  # Collapsible Tree column
            self.toc_tree.heading("Offset", text="Offset", anchor="center")
            self.toc_tree.heading("Size", text="Size", anchor="center")
            self.toc_tree.heading("Keyframes", text="Keyframes", anchor="center")

            self.toc_tree.column("#0", width=200, anchor="w")
            self.toc_tree.column("Offset", width=120, anchor="center")
            self.toc_tree.column("Size", width=100, anchor="center")
            self.toc_tree.column("Keyframes", width=100, anchor="center")

            # Add the root node
            root_node = self.toc_tree.insert("", "end", text="Root", open=True)
            logging.debug(f"Inserted root node with ID: {root_node}")

            # Extract file_length from toc_data if available
            file_length = toc_data.get("file_length", None)

            # Remove 'file_length' from toc_data to avoid processing it as a sector
            toc_data = {k: v for k, v in toc_data.items() if k != "file_length"}

            # Parse and group TOC entries by asset_id
            parent_child_map = {}
            for key, details in toc_data.items():
                parent_id = details["asset_id"]
                if parent_id not in parent_child_map:
                    parent_child_map[parent_id] = []
                parent_child_map[parent_id].append(details)
                logging.debug(f"Grouped entry {key} under parent_id {hex(parent_id)}")

            # Populate Treeview with hierarchical structure
            for parent_id, entries in parent_child_map.items():
                # Add parent node
                parent_node = self.toc_tree.insert(
                    root_node,
                    "end",
                    text=f"Parent {hex(parent_id)}",
                    values=(
                        hex(entries[0]["animation_offset"]),  # First offset for the parent
                        "-",  # Parent does not show a file size
                        "-",  # Parent does not show keyframes
                    )
                )
                logging.debug(f"Inserted parent node {parent_node} for asset_id {hex(parent_id)}")

                # Sort entries based on animation_offset for accurate size calculation
                sorted_entries = sorted(entries, key=lambda x: x["animation_offset"])

                for i, entry in enumerate(sorted_entries):
                    num_keyframes = entry["num_keyframes"]
                    animation_offset = entry["animation_offset"]
                    child_id = f"Child {entry['child_id']}"

                    # Calculate size
                    if i < len(sorted_entries) - 1:
                        next_offset = sorted_entries[i + 1]["animation_offset"]
                        size_bytes = next_offset - animation_offset
                    elif file_length:
                        # Calculate size based on file_length for the last entry
                        size_bytes = file_length - animation_offset
                    else:
                        # If file_length is not available
                        size_bytes = "unknown"

                    size_formatted = self.format_size(size_bytes) if isinstance(size_bytes, int) else size_bytes

                    # Add child node under parent
                    child_node = self.toc_tree.insert(
                        parent_node,
                        "end",
                        text=child_id,
                        values=(hex(animation_offset), size_formatted, num_keyframes)
                    )
                    logging.debug(f"Inserted child node {child_node} for child_id {child_id}: Offset={hex(animation_offset)}, Size={size_formatted}, Keyframes={num_keyframes}")

                    # Optionally, add keyframe sub-entries
                    for frame_index in range(num_keyframes):
                        keyframe_node = self.toc_tree.insert(
                            child_node,
                            "end",
                            text=f"Keyframe {frame_index + 1}",
                            values=("-", "-", "-")  # Placeholder values
                        )
                        logging.debug(f"Inserted keyframe node {keyframe_node} for Keyframe {frame_index + 1}")

            self.display_result("TOC populated successfully.")

        except Exception as e:
            logging.exception("An error occurred while populating TOC")
            self.display_error(f"Error populating TOC: {e}")

    def extract_animation(self):
        """Extract the selected animation with specific structure."""
        selected_item = self.toc_tree.focus()
        if not selected_item:
            self.display_error("Please select an animation to extract.")
            return

        animation_data = self.toc_tree.item(selected_item, "values")
        if not animation_data:
            self.display_error("No animation data available for extraction.")
            return

        # Extract relevant data
        offset_str, size_str, keyframes_str = animation_data
        try:
            animation_offset = 16  # 0x10, fixed offset for animation data
            num_keyframes = int(keyframes_str)
            if size_str != "unknown":
                size_bytes = self.parse_size(size_str)
            else:
                # Calculate size based on file size
                with open(self.file_path.get(), 'rb') as f:
                    f.seek(0, 2)  # Seek to end to get file size
                    file_length = f.tell()
                    size_bytes = file_length - animation_offset
                    logging.warning("Size is unknown. Calculated size based on file length.")
        except ValueError:
            self.display_error("Invalid animation size.")
            return

        # Open a save file dialog to select output path
        output_path = filedialog.asksaveasfilename(
            title="Save Extracted Animation",
            defaultextension=".anim",  # Replace with appropriate extension
            filetypes=[("Animation Files", "*.anim"), ("All files", "*.*")]
        )

        if not output_path:
            # User canceled the save dialog
            return

        try:
            # Read animation data from the source file
            with open(self.file_path.get(), 'rb') as f:
                f.seek(int(offset_str, 16))
                animation_content = f.read(size_bytes)

            # Calculate total file size (header + animation data)
            total_file_size = 16 + len(animation_content)  # 16 bytes for header

            # Prepare header and metadata
            header = b'ANIM'  # 4-byte header
            total_size_bytes = struct.pack('I', total_file_size)  # 4-byte unsigned int
            num_keyframes_bytes = struct.pack('I', num_keyframes)  # 4-byte unsigned int
            reserved = b'\x00\x00\x00\x00'  # 4 bytes reserved

            # Write to the output file with the specified structure
            with open(output_path, 'wb') as out_file:
                out_file.write(header)  # Write header at 0x00-0x03
                out_file.write(total_size_bytes)  # Write total file size at 0x04-0x07
                out_file.write(num_keyframes_bytes)  # Write number of keyframes at 0x08-0x0B
                out_file.write(reserved)  # Write reserved bytes at 0x0C-0x0F
                out_file.write(animation_content)  # Write animation data starting at 0x10

            self.display_result(f"Animation extracted successfully to {output_path}.")
        except Exception as e:
            logging.exception("Error extracting animation")
            self.display_error(f"Error extracting animation: {e}")

    def analyze_animation(self):
        """Analyze the selected animation."""
        selected_item = self.toc_tree.focus()
        if not selected_item:
            self.display_error("Please select an animation to analyze.")
            return

        animation_data = self.toc_tree.item(selected_item, "values")
        if not animation_data:
            self.display_error("No animation data available for analysis.")
            return

        # Extract relevant data
        offset_str, size_str, keyframes_str = animation_data
        try:
            animation_offset = int(offset_str, 16)
            num_keyframes = int(keyframes_str)
            if size_str != "unknown":
                size_bytes = self.parse_size(size_str)
            else:
                # Calculate size based on file size
                with open(self.file_path.get(), 'rb') as f:
                    f.seek(0, 2)  # Seek to end to get file size
                    file_length = f.tell()
                    size_bytes = file_length - animation_offset
                    logging.warning("Size is unknown. Calculated size based on file length.")
        except ValueError:
            self.display_error("Invalid animation size.")
            return

        # Determine if analyzing internal or external data
        # For internal analysis, expect_header=False
        # For external analysis (if applicable), expect_header=True
        # Here, since analyzing internal data, set expect_header=False
        expect_header = False

        # Perform analysis
        analysis_results = CEKeyCheck.chk_data(
            file_path=self.file_path.get(),
            animation_offset=animation_offset,
            size_bytes=size_bytes,
            expect_header=expect_header
        )

        # Display results
        if analysis_results["is_valid"]:
            self.display_result("Animation is valid.")
        else:
            self.display_result("Animation analysis found issues:", is_error=True)
            for issue in analysis_results["issues"]:
                self.display_result(f" - {issue}", is_error=True)

        # Display detailed information
        details = analysis_results.get("details", {})
        if details:
            self.display_result("Detailed Analysis:", is_error=False)
            for key, value in details.items():
                self.display_result(f"{key}: {value}", is_error=False)

        # Optionally, offer to export the analysis report
        export = messagebox.askyesno("Export Report", "Would you like to export the analysis report?")
        if export:
            self.display_analysis_report(analysis_results)

    def analyze_exported_anim(self):
        """Analyze an exported .anim file with the custom header."""
        # Open a file dialog to select the .anim file
        anim_file_path = filedialog.askopenfilename(
            title="Select Exported Animation File",
            filetypes=[("Animation Files", "*.anim"), ("All files", "*.*")]
        )

        if not anim_file_path:
            # User canceled the file dialog
            return

        try:
            with open(anim_file_path, 'rb') as f:
                # Read the total file size from the header
                f.seek(4)  # Offset 0x04
                total_size_bytes = struct.unpack('I', f.read(4))[0]
            
                # Read the number of keyframes from the header
                f.seek(8)  # Offset 0x08
                num_keyframes = struct.unpack('I', f.read(4))[0]
            
                # The actual animation data starts at offset 0x10
                animation_offset = 16  # 0x10
                size_bytes = total_size_bytes - animation_offset

        except Exception as e:
            self.display_error(f"Error reading .anim file: {e}")
            return

        # Perform analysis with expect_header=True
        analysis_results = CEKeyCheck.chk_data(
            file_path=anim_file_path,
            animation_offset=animation_offset,
            size_bytes=size_bytes,
            expect_header=True
        )

        # Display results
        if analysis_results["is_valid"]:
            self.display_result("Exported animation is valid.")
        else:
            self.display_result("Exported animation analysis found issues:", is_error=True)
            for issue in analysis_results["issues"]:
                self.display_result(f" - {issue}", is_error=True)

        # Display detailed information
        details = analysis_results.get("details", {})
        if details:
            self.display_result("Detailed Analysis:", is_error=False)
            for key, value in details.items():
                self.display_result(f"{key}: {value}", is_error=False)

        # Optionally, offer to export the analysis report
        export = messagebox.askyesno("Export Report", "Would you like to export the analysis report?")
        if export:
            self.display_analysis_report(analysis_results)


    def display_analysis_report(self, analysis_results):
        """Export analysis results to a file."""
        report = f"Analysis Report:\n"
        report += f"Is Valid: {analysis_results['is_valid']}\n"
        report += "Issues:\n"
        for issue in analysis_results["issues"]:
            report += f" - {issue}\n"
        report += "Details:\n"
        for key, value in analysis_results["details"].items():
            report += f"{key}: {value}\n"

        # Prompt user to save the report
        output_path = filedialog.asksaveasfilename(
            title="Save Analysis Report",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All files", "*.*")]
        )

        if output_path:
            try:
                with open(output_path, 'w') as report_file:
                    report_file.write(report)
                self.display_result(f"Analysis report saved to {output_path}.")
            except Exception as e:
                self.display_error(f"Error saving report: {e}")

    def format_size(self, size_bytes):
        """Convert bytes to a human-readable string."""
        if size_bytes == "unknown":
            return "unknown"

        if size_bytes < 0:
            return "invalid"

        for unit in ['Bytes', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} PB"

    def parse_size(self, size_str):
        """Convert a human-readable size string back to bytes."""
        size_str = size_str.strip().upper()
        units = {"BYTES": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4, "PB": 1024**5}
        try:
            number, unit = size_str.split()
            number = float(number)
            if unit in units:
                return int(number * units[unit])
            else:
                return "unknown"
        except Exception:
            return "unknown"

    def display_result(self, result, is_error=False):
        """Display a result in the log with optional error formatting."""
        if is_error:
            self.result_text.insert(tk.END, f"ERROR: {result}\n", "error")
        else:
            self.result_text.insert(tk.END, result + "\n")
        self.result_text.see(tk.END)

    def display_error(self, error_message):
        """Display an error message."""
        messagebox.showerror("Error", error_message)

    def show_about(self):
        """Show the About dialog."""
        messagebox.showinfo("About", "YMKs Tool\nVersion 1.0\nPowered by Python")


if __name__ == "__main__":
    app = YMKsTool()
    app.mainloop()
