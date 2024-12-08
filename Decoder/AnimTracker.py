import struct
from typing import Optional
from Decoder.AnimGetter import CEKey

class CEKeyTracker:
    @staticmethod
    def chk_track(file_path: str, param1: int, param2: int, param3: int, param4: int) -> Optional[int]:
        """
        Performs track checking based on input parameters and data in the binary file.

        :param file_path: Path to the binary file
        :param param1: First parameter for calculations
        :param param2: Second parameter for calculations
        :param param3: Third parameter for calculations
        :param param4: Fourth parameter for additional data adjustment
        :return: Validation result or None if conditions fail
        """
        try:
            # Simulate assembly registers using Python variables
            s3 = param1  # A1 -> s3
            s2 = param2  # A2 -> s2
            s1 = param3  # A3 -> s1
            s0 = param4  # T0 -> s0

            # Call the Search function
            offset = CEKey._search(file_path, s3, s2, s1, None)
            if offset is None:
                print("Search function returned None.")
                return None

            # Perform the first set of checks
            with open(file_path, 'rb') as f:
                f.seek(offset)
                track_data = struct.unpack('I', f.read(4))[0]  # Load track data

                # Modify data based on conditions
                if track_data != 0:
                    current_value = struct.unpack('I', f.read(4))[0]
                    f.seek(current_value + 4)
                    updated_value = struct.unpack('I', f.read(4))[0] + 1
                    f.seek(current_value + 4)
                    f.write(struct.pack('I', updated_value))

                # Logical conditions and data validation
                while True:
                    shifted_value = updated_value << 4  # SLL operation
                    f.seek(shifted_value + 2)
                    extracted_value = struct.unpack('H', f.read(2))[0] & 0x3FFF

                    # Compare with s3 and s2
                    if s3 != extracted_value:
                        print(f"Value mismatch: {s3} != {extracted_value}")
                        return None

                    # Load more data and validate
                    f.seek(shifted_value + 1)
                    byte_data = struct.unpack('B', f.read(1))[0]
                    if s2 != byte_data:
                        print(f"Byte mismatch: {s2} != {byte_data}")
                        return None

                    f.seek(shifted_value)
                    byte_data = struct.unpack('B', f.read(1))[0]
                    if byte_data < s1 or s0 < byte_data:
                        print("Condition out of bounds.")
                        return None

                    updated_value += 0x10
                    if updated_value >= struct.unpack('I', f.read(4))[0]:
                        break

            # Return success if all conditions pass
            return 1
        except Exception as e:
            print(f"Error in chk_track: {e}")
            return None
