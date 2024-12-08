import struct
import random
from typing import Optional
from Decoder.AnimGetter import CEKey


class CEKeyRandom:
    @staticmethod
    def get_max_sub_rand(file_path: str, param1: int, param2: int) -> Optional[int]:
        """
        Performs a calculation to determine the maximum sub-random value based on input parameters.

        :param file_path: Path to the binary file
        :param param1: First parameter for calculations
        :param param2: Second parameter for calculations
        :return: Calculated value or None on failure
        """
        try:
            s2 = param1  # Assign param1 to s2
            s1 = param2  # Assign param2 to s1
            s0 = 0       # Initialize s0 to zero

            # Call the Search function
            offset = CEKey._search(file_path, s2, s1, s0, None)
            if offset is None:
                print("Search function returned None.")
                return None

            # Check if s0 is non-zero
            if s0 != 0:
                return -1

            # Generate a random value
            rand_value = random.randint(0, 0xFFFFFFFF)

            # Divide random value by s0 if s0 is non-zero (avoid division by zero)
            if s0 != 0:
                try:
                    result = rand_value // s0
                except ZeroDivisionError:
                    print("Division by zero error.")
                    return None
            else:
                # Simulate the `break` behavior
                print("Breaking due to zero divisor.")
                return None

            # Return the modulus value from the division
            return result % s0 if s0 != 0 else None

        except Exception as e:
            print(f"Error in get_max_sub_rand: {e}")
            return None