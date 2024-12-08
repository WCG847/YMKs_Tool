import struct
from typing import Optional
from Decoder.AnimGetter import CEKey

class CEKeyCheck:
    @staticmethod
    def chk_data(file_path: str, param1: int, param2: int, param3: int, param4: Optional[int] = None) -> bool:
        """
        Performs a check based on given parameters and file data.

        :param file_path: Path to the binary file
        :param param1: First parameter for calculations
        :param param2: Second parameter for calculations
        :param param3: Third parameter for calculations
        :param param4: Optional fourth parameter for additional data adjustment
        :return: Boolean result based on logical checks
        """
        try:
            with open(file_path, 'rb') as f:
                # Simulate calling the Search function
                offset = CEKey._search(file_path, param1, param2, param3)
                if offset is None:
                    print("Search function returned None.")
                    return False

                # Step 1: Retrieve base value from the file
                f.seek(offset)
                base_value = struct.unpack('I', f.read(4))[0]

                # Step 2: Calculate logical offsets and values
                logical_offset = base_value * 16  # Multiplied by 0x10
                f.seek(logical_offset + param1)
                calculated_value = struct.unpack('I', f.read(4))[0]

                # Additional parameter modification
                if param4 is not None:
                    param4_offset = param4 * 16
                    f.seek(param4_offset + param2)
                    adjusted_value = struct.unpack('I', f.read(4))[0]
                else:
                    adjusted_value = calculated_value  # Use the calculated value if no param4 provided

                # Step 3: Perform condition checks
                if param1 < adjusted_value:
                    print(f"Condition failed: {param1} < {adjusted_value}")
                    return False

                # Step 4: Validate and return results
                validation_offset = logical_offset + param3 * 4
                f.seek(validation_offset)
                validation_value = struct.unpack('I', f.read(4))[0]

                # Logical comparison and final validation
                result = (validation_value ^ 1) & 1  # XOR and mask operation
                return result == 1
        except Exception as e:
            print(f"Error in chk_data: {e}")
            return False