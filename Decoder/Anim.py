import struct
from typing import List, Tuple, Optional
from Decoder.YMKs import YMKs

class CEKey:
    OFFSET_MULTIPLIER = 0x10
    FLAG_CHECK_VALUE = 0x80
    MAX_VALUE = 0xFFFF

    @staticmethod
    def get_data(
        file_path: str,
        search_params: Tuple,
        asset_index: int,
        data_index: int
    ) -> Optional[Tuple[int, List[int]]]:
        """
        Retrieves data based on the search parameters and asset indices.

        :param file_path: Path to the binary file
        :param search_params: Parameters for the search function
        :param asset_index: Index to access specific asset
        :param data_index: Index for data lookup
        :return: Tuple containing the extracted integer and a list of bytes, or None on failure
        """
        try:
            # Call the search function and validate its result
            anim_offset = YMKs.search(*search_params)
            if anim_offset is None:
                raise ValueError("Search failed to locate the animation offset.")

            with open(file_path, 'rb') as f:
                # Step 1: Load base asset
                base_asset = CEKey._read_int(f, anim_offset)
                offset1 = base_asset * CEKey.OFFSET_MULTIPLIER
                offset2 = asset_index * CEKey.OFFSET_MULTIPLIER

                # Step 2: Access first and second values
                first_value = CEKey._read_int(f, anim_offset + offset1)
                second_value = CEKey._read_int(f, anim_offset + offset2)

                # Step 3: Check conditions
                if search_params[0] < first_value:
                    raise ValueError("Search parameter does not meet required conditions.")

                # Extract adjusted data
                extracted_value = second_value - 0x100

                # Step 4: Load further data and validate
                more_data_offset = anim_offset + offset2 + 4
                validation_value = CEKey._read_int(f, more_data_offset)

                if validation_value != CEKey.MAX_VALUE:
                    raise ValueError("Unexpected value found during validation.")

                # Step 5: Process byte data
                data_offset = anim_offset + offset2 + 8
                byte_buffer = CEKey._extract_bytes(f, data_offset, search_params[0])

                return extracted_value, byte_buffer
        except Exception as e:
            print(f"Error in get_data: {e}")
            return None

    @staticmethod
    def _read_int(file, offset: int) -> int:
        """Reads an integer from the file at the given offset."""
        file.seek(offset)
        return struct.unpack('I', file.read(4))[0]

    @staticmethod
    def _extract_bytes(file, offset: int, limit: int) -> List[int]:
        """Extracts bytes from the file starting at the given offset."""
        file.seek(offset)
        byte = struct.unpack('B', file.read(1))[0]
        if byte & CEKey.FLAG_CHECK_VALUE == 0:
            raise ValueError("Data byte flag check failed.")

        # Strip the flag bit
        byte &= ~CEKey.FLAG_CHECK_VALUE
        buffer = [byte]

        # Continue extracting while within limit
        while limit >= byte:
            byte += 1
            file.seek(offset + byte)
            buffer.append(struct.unpack('B', file.read(1))[0])

        return buffer
