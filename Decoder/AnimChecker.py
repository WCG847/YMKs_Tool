import struct
from typing import Optional
from Decoder.YMKs import YMKs
import logging

class CEKeyCheck:
    @staticmethod
    def chk_data(file_path: str, animation_offset: int, size_bytes: int, expect_header: bool = False) -> dict:
        """
        Analyzes animation data for integrity and consistency.
        Optionally checks for a custom header if exporting externally.
        
        :param file_path: Path to the binary file
        :param animation_offset: Offset where the animation data starts
        :param size_bytes: Size of the animation data in bytes
        :param expect_header: Whether to expect a custom header in the data
        :return: Dictionary containing analysis results
        """
        analysis_results = {
            "is_valid": True,
            "issues": [],
            "details": {}
        }
        try:
            with open(file_path, 'rb') as f:
                if expect_header:
                    # Read Header (0x00-0x03)
                    f.seek(0)
                    header = f.read(4)
                    if header != b'ANIM':
                        analysis_results["is_valid"] = False
                        analysis_results["issues"].append("Invalid header. Expected 'ANIM'.")
                    
                    # Read Total File Size (0x04-0x07)
                    total_size_bytes = struct.unpack('I', f.read(4))[0]
                    analysis_results["details"]["Total File Size"] = total_size_bytes
                    
                    # Read Number of Keyframes (0x08-0x0B)
                    num_keyframes = struct.unpack('I', f.read(4))[0]
                    analysis_results["details"]["Number of Keyframes"] = num_keyframes
                    
                    # Read Reserved Bytes (0x0C-0x0F)
                    reserved = f.read(4)
                    analysis_results["details"]["Reserved"] = reserved.hex()
                    
                    # Set animation data offset to 0x10
                    f.seek(16)
                    animation_data = f.read(size_bytes)
                else:
                    # Analyze raw animation data without header
                    f.seek(animation_offset)
                    animation_data = f.read(size_bytes)
    
                # Example Analysis: Check for excessive null bytes
                # Define a threshold for acceptable null bytes (e.g., less than 5% of data)
                null_byte_count = animation_data.count(b'\x00')
                null_byte_percentage = (null_byte_count / len(animation_data)) * 100 if len(animation_data) > 0 else 0
                analysis_results["details"]["Null Byte Count"] = null_byte_count
                analysis_results["details"]["Null Byte Percentage"] = f"{null_byte_percentage:.2f}%"
                
                if null_byte_percentage > 15:  # Threshold can be adjusted
                    analysis_results["is_valid"] = False
                    analysis_results["issues"].append("Excessive null bytes detected in animation data.")
    
                # Example Analysis: Validate expected size
                actual_size = len(animation_data)
                analysis_results["details"]["Expected Size"] = size_bytes
                analysis_results["details"]["Actual Size"] = actual_size
                if actual_size != size_bytes:
                    analysis_results["is_valid"] = False
                    analysis_results["issues"].append(f"Expected animation size {size_bytes} bytes, but found {actual_size} bytes.")
    
                # Additional integrity checks can be added here based on known data structures
                # For example, verifying specific byte patterns or checksum values
    
            return analysis_results
    
        except Exception as e:
            logging.exception(f"Error in chk_data: {e}")
            analysis_results["is_valid"] = False
            analysis_results["issues"].append(f"Error during analysis: {e}")
            return analysis_results
