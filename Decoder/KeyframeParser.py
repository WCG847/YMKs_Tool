import struct
import logging
from typing import List, Tuple, Optional

class Keyframe:
    def __init__(self, index: int, header: int, offset: int, size: int, data: bytes):
        self.index = index
        self.header = header
        self.offset = offset
        self.size = size
        self.raw_data = data
        self.rotation = self.parse_rotation()
        self.position = self.parse_position()

    def parse_rotation(self) -> Tuple[float, float, float]:
        """
        Parses rotation data from raw keyframe bytes.
        Adjust the parsing logic based on actual data format.
        """
        # Example: Assume rotation is stored as three consecutive floats (12 bytes)
        if len(self.raw_data) < 12:
            logging.error(f"Insufficient data for rotation in keyframe {self.index}.")
            return (0.0, 0.0, 0.0)
        rotation = struct.unpack('fff', self.raw_data[:12])
        return rotation

    def parse_position(self) -> Tuple[float, float, float]:
        """
        Parses position data from raw keyframe bytes.
        Adjust the parsing logic based on actual data format.
        """
        # Example: Assume position is stored as three consecutive floats (12 bytes) after rotation
        if len(self.raw_data) < 24:
            logging.error(f"Insufficient data for position in keyframe {self.index}.")
            return (0.0, 0.0, 0.0)
        position = struct.unpack('fff', self.raw_data[12:24])
        return position

    def __str__(self):
        return (f"Keyframe {self.index}: Header={hex(self.header)}, Offset={hex(self.offset)}, "
                f"Size={self.size} bytes, Rotation={self.rotation}, Position={self.position}")

class KeyframeParser:
    FLAG_CHECK_VALUE = 0x80
    MAX_VALUE = 0xFFFF

    def __init__(self, file_path: str, animation_offset: int, size_bytes: int):
        self.file_path = file_path
        self.animation_offset = animation_offset
        self.size_bytes = size_bytes
        self.keyframes: List[Keyframe] = []

    def parse_keyframes(self) -> bool:
        """
        Parses keyframes from the animation data based on header byte logic.
        Returns True if parsing is successful, False otherwise.
        """
        try:
            with open(self.file_path, 'rb') as f:
                f.seek(self.animation_offset)
                animation_data = f.read(self.size_bytes)
                if not animation_data:
                    logging.error("No animation data found.")
                    return False

                # Initialize parsing indices
                byte_index = 0
                total_bytes = len(animation_data)
                keyframe_index = 1

                while byte_index < total_bytes:
                    if byte_index + 1 > total_bytes:
                        logging.warning(f"Insufficient data for keyframe {keyframe_index} header.")
                        break

                    # Read header byte
                    header_byte = animation_data[byte_index]
                    logging.debug(f"Keyframe {keyframe_index} Header: {hex(header_byte)}")
                    byte_index += 1

                    # Validate and calculate actual size
                    if header_byte < self.FLAG_CHECK_VALUE:
                        logging.error(f"Invalid header byte {hex(header_byte)} for keyframe {keyframe_index}.")
                        break

                    actual_size = (header_byte - self.FLAG_CHECK_VALUE) << 1
                    logging.debug(f"Keyframe {keyframe_index} Actual Size: {actual_size} bytes")

                    # Check if there are enough bytes left for this keyframe
                    if byte_index + actual_size > total_bytes:
                        logging.warning(f"Insufficient data for keyframe {keyframe_index}. Expected {actual_size} bytes.")
                        break

                    # Read keyframe data
                    keyframe_data = animation_data[byte_index:byte_index + actual_size]
                    keyframe_offset = self.animation_offset + byte_index
                    logging.debug(f"Keyframe {keyframe_index} Offset: {hex(keyframe_offset)}")

                    # Create Keyframe object
                    keyframe = Keyframe(
                        index=keyframe_index,
                        header=header_byte,
                        offset=keyframe_offset,
                        size=actual_size,
                        data=keyframe_data
                    )
                    self.keyframes.append(keyframe)
                    logging.info(str(keyframe))

                    # Move to the next keyframe
                    byte_index += actual_size
                    keyframe_index += 1

            logging.info(f"Successfully parsed {len(self.keyframes)} keyframes.")
            return True

        except Exception as e:
            logging.exception(f"Error parsing keyframes: {e}")
            return False

    def get_keyframes(self) -> List[Keyframe]:
        """Returns the list of parsed keyframes."""
        return self.keyframes
