import struct
from typing import Optional

class YMKs:
    TOC_OFFSET = 0x100
    ASSET_TABLE_OFFSET = 0x104
    ENTRY_SIZE = 0x10

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
            
                f.seek(YMKs.ASSET_TABLE_OFFSET)
                asset_table_start = struct.unpack('I', f.read(4))[0]
                anim_sector_start = asset_table_start + (toc_count * YMKs.ENTRY_SIZE)
            
                for index in range(toc_count):
                    entry_offset = asset_table_start + (index * YMKs.ENTRY_SIZE)
                    f.seek(entry_offset)
                    _, _, rel_offset, num_keyframes = struct.unpack('HHII', f.read(12))
                
                    anim_offset_pos = anim_sector_start + rel_offset
                    f.seek(anim_offset_pos)
                    anim_data = struct.unpack('I', f.read(4))[0]
                
                    if anim_data == anim_offset:
                        keyframes = []
                        for frame in range(num_keyframes):
                            f.seek(anim_offset_pos + frame * 4)
                            keyframes.append(struct.unpack('I', f.read(4))[0])
                        print(f"Keyframes found: {keyframes}")
                        return anim_offset_pos

                print("Animation data not found or anim_offset mismatch.")
                return None
        except Exception as e:
            print(f"Error during search: {e}")
            return None
