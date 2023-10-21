def format_data(data, data_len):
    if type(data) != bytes:
        data = data.encode("utf-8")
    assert len(data) <= data_len, "data too large"
    if len(data) < data_len:
        padding = b'\x00'*(data_len-len(data))
        data = data + padding
    return data
