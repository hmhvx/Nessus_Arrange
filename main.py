import tkinter as tk
from tkinter import filedialog
import pandas as pd
import tkinter as tk
from tkinter import filedialog
import os


# 读取CSV文件并转换成EXECL文件
def read_write_csv_xlsx(input_file, output_file):
    df = pd.read_csv(input_file)
    num = 1
    for index, row in df.iterrows():
        df.loc[index, 'Plugin ID'] = num
        num += 1
    df = df.rename(columns={'Plugin ID': '序号', 'Host': '主机', 'Port': '端口', 'Name': '漏洞名称'})
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
    # 清洗 Port 为 0 和 Plugin Output 为 Up
    df = df.drop(df[(df['Port'] == str("0")) & (df['Plugin Output'] == 'Up')].index)
    # 清洗 Port 为 0 和 Plugin Output 为 Down
    df = df.drop(df[(df['Port'] == str("0")) & (df['Plugin Output'] == 'Down')].index)
    # 重新标记UDP协议端口为 0 则 为Down
    for index, row in df.iterrows():
        if df.loc[int(index), 'Port'] == "['0']" and df.loc[int(index), 'Protocol'] == 'udp':
            df.loc[int(index), 'Plugin Output'] = "Down"
    num = 1
    for index, row in df.iterrows():
        df.loc[index, 'Plugin ID'] = num
        num += 1
    # 写入文件
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


if __name__ == '__main__':
    # 创建文件夹
    os.makedirs("output", exist_ok=True)
    # 获取当前工作目录
    work_path = os.getcwd()
    # 切换到output文件夹
    os.chdir(work_path + "/output")
    # 获取文件路径
    input_file_path = filedialog.askopenfilename()
    # 获取保存文件名
    filename = filedialog.asksaveasfilename()
    # 示例用法
    read_write_csv_xlsx(input_file_path, filename + '_源文件.xlsx')
    read_write_csv_prot(input_file_path, filename + '_端口文件.xlsx')
    read_write_csv_vuln(input_file_path, filename + '_漏洞文件.xlsx')
