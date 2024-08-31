import re
import pandas as pd

# Initialize lists to store data for each frame
frames = []

# Define regular expressions to capture necessary fields
patterns = {
    "Frame Number": r"Frame Number:\s+(\d+)",
    "Frame Length": r"Frame Length:\s+(\d+)\s+bytes",
    "Arrival Time": r"Arrival Time:\s+(.+)",
    "Source IP": r"Source Address:\s+([\d\.]+)",
    "Destination IP": r"Destination Address:\s+([\d\.]+)",
    "Source Port": r"Source Port:\s+(\d+)",
    "Destination Port": r"Destination Port:\s+(\d+)",
    "Protocol": r"Protocol:\s+(\w+)",
    "Time to Live": r"Time to Live:\s+(\d+)",
    "Flags": r"Flags:\s+0x(\w+)",
    "Sequence Number": r"Sequence Number:\s+(\d+)",
    "Acknowledgment Number": r"Acknowledgment Number:\s+(\d+)",
    "Window Size": r"Window:\s+(\d+)",
    "Checksum Status": r"Checksum Status:\s+(\w+)",
}

# Open the text file for reading
with open('/Users/architanant/Documents/HAWKS/test/out.txt', 'r') as file:
    frame_data = {}
    for line in file:
        line = line.strip()
        
        # Check for the start of a new frame
        if line.startswith("Frame "):
            if frame_data:
                frames.append(frame_data)  # Save the previous frame's data
            frame_data = {}  # Start new frame data
        
        # Extract data based on patterns
        for key, pattern in patterns.items():
            match = re.search(pattern, line)
            if match:
                frame_data[key] = match.group(1)
    
    # Add the last frame's data
    if frame_data:
        frames.append(frame_data)

# Convert the list of frames to a Pandas DataFrame
df = pd.DataFrame(frames)

# Save to CSV
df.to_csv("pcapng_dataset.csv", index=False)

print("Dataset created successfully!")