import struct
from typing import Optional

class YMKs:
    TOC_OFFSET = 0x100  # Start of the TOC
    ASSET_TABLE_OFFSET = 0x104  # Start of the Asset Table
    ENTRY_SIZE = 0x10  # Size of each entry in the TOC

    @staticmethod
    def search(file_path: str, sector_offset: int, anim_offset: int, keyframes_count: int) -> Optional[int]:
        """
        Searches for animation data in a binary file.

        :param file_path: Path to the binary file
        :param sector_offset: Offset to the animation sector
        :param anim_offset: Expected animation offset
        :param keyframes_count: Number of keyframes to process
        :return: Offset of the animation data, or None if not found
        """
        try:
            with open(file_path, 'rb') as f:
                f.seek(YMKs.TOC_OFFSET)
                toc_count = struct.unpack('H', f.read(2))[0]

                asset_table_start = YMKs.ASSET_TABLE_OFFSET
                print(f"Asset Table Start: {hex(asset_table_start)}")

                anim_sector_start = asset_table_start + (toc_count * YMKs.ENTRY_SIZE)

                for index in range(toc_count):
                    entry_offset = asset_table_start + (index * YMKs.ENTRY_SIZE)
                    f.seek(entry_offset)
                    # Unpack all 16 bytes
                    child_id, asset_id, rel_offset, num_keyframes, unknown_field = struct.unpack('HHIII', f.read(16))

                    anim_offset_pos = anim_sector_start + rel_offset
                    f.seek(anim_offset_pos)
                    anim_data = struct.unpack('I', f.read(4))[0]

                    if anim_data == anim_offset:
                        keyframes = []
                        for frame in range(num_keyframes):
                            frame_offset = anim_offset_pos + frame * 4
                            f.seek(frame_offset)
                            keyframes.append(struct.unpack('I', f.read(4))[0])
                        print(f"Keyframes found: {keyframes}")
                        return anim_offset_pos

                print("Animation data not found or anim_offset mismatch.")
                return None

        except Exception as e:
            print(f"Error during search: {e}")
            return None


    @staticmethod
    def build_toc(file_path: str) -> Optional[dict]:
        try:
            with open(file_path, 'rb') as f:
                f.seek(YMKs.TOC_OFFSET)
                toc_count = struct.unpack('H', f.read(2))[0]
                print(f"TOC Count: {toc_count}")

                asset_table_start = YMKs.ASSET_TABLE_OFFSET
                anim_sector_start = asset_table_start + (toc_count * YMKs.ENTRY_SIZE)
                print(f"Asset Table Start: {hex(asset_table_start)}, Anim Sector Start: {hex(anim_sector_start)}")

                f.seek(0, 2)
                file_length = f.tell()

                toc = {}
                for index in range(toc_count):
                    entry_offset = asset_table_start + (index * YMKs.ENTRY_SIZE)
                    if entry_offset + YMKs.ENTRY_SIZE > file_length:
                        print(f"Skipping invalid entry offset: {entry_offset}")
                        continue

                    f.seek(entry_offset)
                    header = f.read(YMKs.ENTRY_SIZE)
                    if len(header) < YMKs.ENTRY_SIZE:
                        print(f"Incomplete TOC entry at offset {entry_offset}")
                        continue

                    child_id, asset_id, rel_offset, num_keyframes, unknown_field = struct.unpack('HHIII', header)
                    print(
                        f"Entry {index}: child_id={child_id}, asset_id={asset_id}, rel_offset={hex(rel_offset)}, "
                        f"num_keyframes={num_keyframes}, unknown_field={unknown_field}"
                    )

                    anim_offset_pos = anim_sector_start + rel_offset
                    if anim_offset_pos >= file_length or anim_offset_pos < anim_sector_start:
                        print(f"Skipping invalid animation offset: {hex(anim_offset_pos)}")
                        continue

                    animations = []
                    for frame in range(num_keyframes):
                        frame_offset = anim_offset_pos + frame * 4
                        if frame_offset + 4 > file_length:
                            print(f"Skipping frame offset {frame_offset} (exceeds file length)")
                            break

                        f.seek(frame_offset)
                        frame_data = struct.unpack('I', f.read(4))[0]
                        animations.append(frame_data)

                    toc[f"Sector_{index}"] = {
                        "child_id": child_id,
                        "asset_id": asset_id,
                        "animation_offset": anim_offset_pos,
                        "num_keyframes": num_keyframes,
                        "animations": animations,  # Ensure this is a list
                        "unknown_field": unknown_field,
                    }

                return toc

        except Exception as e:
            print(f"Error building TOC: {e}")
            return None


