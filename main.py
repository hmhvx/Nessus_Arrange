import pandas as pd
from tkinter import filedialog


"""
Nessus 报告整理工具
1. 读取CSV文件并转换成EXECL文件
2. 整理出端口文件
3. 整理出漏洞文件
4. 整理出高危端口文件
"""


# 读取CSV文件并转换成EXECL文件
def read_write_csv_xlsx(input_file, output_file):
    df = pd.read_csv(input_file)
    num = 1
    for index, row in df.iterrows():
        df.loc[index, 'Plugin ID'] = num
        num += 1
    df.to_excel(output_file, index=False)


# 读取CSV文件并整理出端口文件
def read_write_csv_prot(input_file, output_file):
    # 读取CSV文件
    df = pd.read_csv(input_file)
    # 设置Host列为字符串类型
    df['Host'] = df['Host'].astype(str)
    # 设置Port列为字符串类型
    df['Port'] = df['Port'].astype(str)
    # 判断端口是否存活
    for index, row in df.iterrows():
        if 'Ping the remote host' in df.loc[index, 'Name']:
            df.loc[index, "Plugin Output"] = "Down"
        else:
            df.loc[index, "Plugin Output"] = "Up"
            # 组合端口
    str_num = ['0']
    for index, row in df.iterrows():
        if list(df.index)[-1] != index:
            if df.loc[int(index) + 1, 'Host'] == df.loc[int(index), 'Host']:
                if str_num.count(df.loc[int(index), 'Port']) == 1:
                    df.loc[int(index), 'Port'] = '0'
                else:
                    str_num.append(str(df.loc[int(index), 'Port']))
                    df.loc[int(index), 'Port'] = '0'
            else:
                df.loc[int(index), 'Port'] = str(str_num)
                str_num.clear()
                str_num.append('0')
        else:
            df.loc[int(index), 'Port'] = str(str_num)
            str_num.clear()
            str_num.append('0')
            # 重新标记UDP协议端口为 0 则 为Down
    for index, row in df.iterrows():
        if df.loc[int(index), 'Port'] == "['0']" and df.loc[int(index), 'Protocol'] == 'udp':
            df.loc[int(index), 'Plugin Output'] = "Down"
    num = 1
    for index, row in df.iterrows():
        df.loc[index, 'Plugin ID'] = num
        num += 1
    df.to_excel(output_file, index=False)


# 读取CSV文件并输出漏洞XLSX文件
def read_write_csv_vuln(input_file, output_file):
    df = pd.read_csv(input_file)
    df = df.dropna(subset=['Risk'])
    num = 1
    for index, row in df.iterrows():
        df.loc[index, 'Plugin ID'] = num
        num += 1
    df.to_excel(output_file, index=False)


def filter_and_log_unique_hosts_per_port(input_file, output_file_txt):
    # 读取csv文件至DataFrame
    df = pd.read_csv(input_file)

    # 确保Port列为字符串类型，以便进行匹配
    df['Port'] = df['Port'].astype(str)

    # 筛选Port列中值为22、3389、445、135或139的行
    filtered_df = df[df['Port'].isin(['22', '3389', '445', '135', '139'])]

    # 对于Port列值相同的行，保留每种Port-Host组合的第一次出现
    # 首先按Port列排序，然后按Host列分组，选取每个分组的第一条记录
    final_df = filtered_df.sort_values(['Port', 'Host']).drop_duplicates(subset=['Port', 'Host'], keep='first')

    # 保存筛选和去重后的数据到Excel
    # 准备写入TXT的内容
    with open(output_file_txt, 'w') as txt_file:
        for port, group in final_df.groupby('Port'):
            host_list = group['Host'].tolist()
            hosts_str = ', '.join(host_list)
            txt_file.write(f"{port}:{hosts_str}\n")


if __name__ == '__main__':
    # 获取文件路径
    input_file_path = filedialog.askopenfilename()
    # 获取保存文件名
    filename = filedialog.asksaveasfilename()
    # 示例用法
    read_write_csv_xlsx(input_file_path, filename + '_源文件.xlsx')
    read_write_csv_prot(input_file_path, filename + '_端口文件.xlsx')
    read_write_csv_vuln(input_file_path, filename + '_漏洞文件.xlsx')
    filter_and_log_unique_hosts_per_port(input_file_path, filename + '_高危端口文件.txt')
