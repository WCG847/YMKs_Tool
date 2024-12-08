import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Decoder.AnimChecker import CEKeyCheck
from Decoder.AnimGetter import CEKey
from Decoder.AnimRetriever import CEKeyRandom
from Decoder.AnimTracker import CEKeyTracker
from Decoder.YMKs import YMKs


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
        self.toc_tree = ttk.Treeview(frame, columns=("Details"), show="tree")
        self.toc_tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.toc_tree.yview)
        self.toc_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")


    def create_result_log(self):
        """Create result log display."""
        frame = tk.Frame(self)
        frame.pack(pady=10, fill="x")

        tk.Label(frame, text="Result Log:").pack(anchor="w", padx=5)

        self.result_text = tk.Text(frame, height=10, wrap="word")
        self.result_text.pack(fill="x", padx=5, pady=5)

    def create_action_buttons(self):
        """Create buttons for user actions."""
        frame = tk.Frame(self)
        frame.pack(pady=10)

        tk.Button(frame, text="Parse Archive", command=self.parse_archive).pack(side="left", padx=10)
        tk.Button(frame, text="Extract Animation", command=self.extract_animation).pack(side="left", padx=10)
        tk.Button(frame, text="Analyze Animation", command=self.analyze_animation).pack(side="left", padx=10)

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
            if toc_data:
                self.toc_tree.delete(*self.toc_tree.get_children())  # Clear previous TOC
                self.populate_toc(toc_data)
                self.display_result("Archive parsed successfully.")
            else:
                self.display_error("Failed to parse the archive.")
        except Exception as e:
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
            print(f"Inserted root node with ID: {root_node}")

            # Parse and group TOC entries by asset_id
            parent_child_map = {}
            for key, details in toc_data.items():
                parent_id = details["asset_id"]
                if parent_id not in parent_child_map:
                    parent_child_map[parent_id] = []
                parent_child_map[parent_id].append(details)
                print(f"Grouped entry {key} under parent_id {hex(parent_id)}")

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
                print(f"Inserted parent node {parent_node} for asset_id {hex(parent_id)}")

                for entry in entries:
                    num_keyframes = entry["num_keyframes"]
                    animation_offset = entry["animation_offset"]
                    child_id = f"Child {entry['child_id']}"

                    # Add child node under parent
                    child_node = self.toc_tree.insert(
                        parent_node,
                        "end",
                        text=child_id,
                        values=(hex(animation_offset), "unknown", num_keyframes)
                    )
                    print(f"Inserted child node {child_node} for child_id {child_id}")

                    # Optionally, list keyframe data under each child
                    animations = entry.get("animations", [])
                    if not isinstance(animations, list):
                        print(f"Invalid animations format for child_id {child_id}")
                        continue

                    for frame_index, frame_data in enumerate(animations):
                        # Assuming frame_data is keyframe data, not an offset
                        keyframe_text = f"Keyframe {frame_index + 1}"
                        keyframe_value = hex(frame_data)  # Representing keyframe data as hex
                        keyframe_node = self.toc_tree.insert(
                            child_node,
                            "end",
                            text=keyframe_text,
                            values=("-", "-", keyframe_value)
                        )
                        print(f"Inserted keyframe node {keyframe_node} under child {child_id}: {keyframe_text} -> {keyframe_value}")

                    # Debugging Output
                    print(f"Treeview Entry Added: Parent ID: {hex(parent_id)}, Child ID: {child_id}, "
                          f"Offset: {hex(animation_offset)}, Size: unknown, Keyframes: {num_keyframes}")

        except Exception as e:
            self.display_error(f"Error populating TOC: {e}")


    def extract_animation(self):
        """Extract the selected animation."""
        selected_item = self.toc_tree.focus()
        if not selected_item:
            self.display_error("Please select an animation to extract.")
            return

        animation_data = self.toc_tree.item(selected_item, "values")
        if animation_data:
            self.display_result(f"Extracted Animation: {animation_data}")
        else:
            self.display_error("No animation data available for the selected item.")

    def analyze_animation(self):
        """Analyze the selected animation."""
        selected_item = self.toc_tree.focus()
        if not selected_item:
            self.display_error("Please select an animation to analyze.")
            return

        animation_details = self.toc_tree.item(selected_item, "values")
        if animation_details:
            # Example: Analyze using CEKeyCheck
            file_path = self.file_path.get()
            try:
                analysis_result = CEKeyCheck.chk_data(file_path, 0, 0, 0)  # Replace with actual params
                self.display_result(f"Analysis Result: {analysis_result}")
            except Exception as e:
                self.display_error(f"Error analyzing animation: {e}")
        else:
            self.display_error("No animation details available for analysis.")

    def display_result(self, result):
        """Display a result in the log."""
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
