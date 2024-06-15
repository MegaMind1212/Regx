import pandas as pd
import re

file_path = 'Preprocessed_data.csv'
df = pd.read_csv(file_path)

ip_address_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
mac_address_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
error_message_pattern = r'ERROR: .*'

def extract_pattern(text, pattern):
    match = re.search(pattern, text)
    return match.group(0) if match else None

df['ExtractedIPSrc'] = df['ip.src'].apply(lambda x: extract_pattern(str(x), ip_address_pattern))
df['ExtractedIPDst'] = df['ip.dst'].apply(lambda x: extract_pattern(str(x), ip_address_pattern))
df['ExtractedEthSrc'] = df['eth.src'].apply(lambda x: extract_pattern(str(x), mac_address_pattern))
df['ExtractedEthDst'] = df['eth.dst'].apply(lambda x: extract_pattern(str(x), mac_address_pattern))
df['ExtractedErrorMessage'] = df['Value'].apply(lambda x: extract_pattern(str(x), error_message_pattern))

filtered_df = df[
    (df['frame.len'] > 200) &
    (df['ip.proto'] == 6) &
    (df['tcp.len'] > 0) &
    (df['tcp.srcport'] < 1024) &
    (df['normality'] == 0)
]

output_file_path = 'Updated_data_output.csv'
filtered_df.to_csv(output_file_path, index=False)

print("Filtered data saved to", output_file_path)
