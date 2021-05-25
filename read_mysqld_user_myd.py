#!/usr/bin/env python3
# https://dev.mysql.com/doc/internals/en/layout-record-storage-frame.html


def read_len(content, begin, end):
    sum_len = 0
    for bit in content[begin:end]:
        sum_len = (sum_len << 8) + bit
    return sum_len

# 4 bits padding 1 bytes
def pad(data_len):
    byte_len = data_len >> 2
    return (byte_len + ((data_len - (byte_len << 2)) & 1)) << 2

def read_record(content, idx, header_len, data_len_start, data_len_end, next_pos_start=-1, unused_len_pos=0):
    rec_type = content[idx]
    data_len = read_len(content, idx + data_len_start, idx + data_len_end + 1)
    if data_len > len(content):
        return {}
    
    unused_len = unused_len_pos > 0 and content[idx+unused_len_pos] or 0
    
    all_len = header_len + data_len + unused_len

    # padding
    last_2_bit = all_len & 0x03
    if last_2_bit != 0:
        block_len = (all_len >> 2) << 2
        block_len += 4
    else:
        block_len = all_len
 
    if next_pos_start > 0:
        next_pos = read_len(content, idx + next_pos_start, idx + next_pos_start + 8)
        next_record = dispatch_record(content, next_pos)
    else:
        next_record = {}
        
    return dict(
        rec_type=rec_type,
        block_len=block_len,
        data_len=data_len,
        next_rec=next_record,
        data_begin=idx + header_len
    )


def dispatch_record(content, idx):
    record =  {}
    if idx > len(content) - 1:
        # 越界 直接返回
        return record    
    rec_type = content[idx]
    if rec_type == 0:
        record = read_record(content, idx, 20, 1, 3)
    elif rec_type == 1:
        record = read_record(content, idx, 3, 1, 2)
    elif rec_type == 2:
        record = read_record(content, idx, 4, 1, 3)
    elif rec_type == 3:
        record = read_record(content, idx, 4, 1, 2, unused_len_pos=3)
    elif rec_type == 4:
        record = read_record(content, idx, 5, 1, 3, unused_len_pos=4)
    elif rec_type == 5:
        record = read_record(content, idx, 13, 3, 4, 5)
    elif rec_type == 6:
        record = read_record(content, idx, 15, 4, 6, 7)
    elif rec_type == 7:
        record = read_record(content, idx, 3, 1, 2)
    elif rec_type == 8:
        record = read_record(content, idx, 4, 1, 3)
    elif rec_type == 9:
        record = read_record(content, idx, 4, 1, 2, unused_len_pos=3)
    elif rec_type == 10:
        record = read_record(content, idx, 5, 1, 3, unused_len_pos=4)
    elif rec_type == 11:
        record = read_record(content, idx, 11, 1, 2, 3)
    elif rec_type == 12:
        record = read_record(content, idx, 12, 1, 3, 4)
    elif rec_type == 13:
        record = read_record(content, idx, 16, 5, 7, 8)
    return record


def parse_record(record_content, version):
    if version == "5.0" or version == "5.1":
        start_offset = 2
    else:
        start_offset = 3
    user = ""
    password = ""

    # index 跳过host字段 到user length位置
    user_len_index = start_offset + record_content[start_offset] + 1
    user_end_index = user_len_index + 1 + record_content[user_len_index]

    # 取user
    user = user.join(map(chr, record_content[user_len_index+1:user_end_index]))

    for i in range(user_end_index, len(record_content)):
        # 找到'*'
        if record_content[i] == 42:
            # 直接取40位hash
            password = password.join(map(chr, record_content[i+1:i+1+40]))
    return dict(user=user, password=password)

def read_record_content(content, record):
    tmp_buffer = content[record['data_begin']:record['data_begin'] + record['data_len']]
    if record['next_rec']:
        record = record['next_rec']
        tmp_buffer += read_record_content(content, record)
    return tmp_buffer


def read_records(filename, version="5.5"):
    record_list = []
    user_info = {}
    with open(filename, 'rb') as f:
        content = f.read()
        content_len = len(content)
        idx = 0
        while idx < content_len:
            record = dispatch_record(content, idx)
            if not record:
                # record返回空值 跳出
                break
            if 0 < record['rec_type'] <= 6:
                record_list.append(record)
                idx += record['block_len']
            elif record['rec_type'] == 0:
                idx += record['data_len']
            else:
                idx += record['block_len']
    for record in record_list:
        try:
            # 读record_content
            record_content = read_record_content(content, record)
            # 获得user字典 含用户名和密码
            user_info_ret = parse_record(record_content, version)
            if user_info_ret['user']:
                user_info[user_info_ret['user']] = user_info_ret['password']
        except Exception as e:
            print("failed parse record, details: %s.", str(e))
    print(user_info)

def main():
    read_records('/usr/local/var/mysql/mysql/user.MYD')


if __name__ == '__main__':
    main()
