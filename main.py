import pandas as pd


# 读取CSV文件并转换成EXECL文件
def read_write_csv_xlsx(input_file, output_file):
    df = pd.read_csv(input_file)
    df = df.rename(columns={'Plugin ID': '序号', 'Host': '主机', 'Port': '端口', 'Name': '漏洞名称'})
    df.to_excel(output_file, index=False)


# 读取CSV文件并整理出端口文件
def read_write_csv_prot(input_file, output_file):
    df = pd.read_csv(input_file)
    df = df.rename(columns={'Plugin ID': '序号', 'Host': '主机', 'Port': '端口', 'Name': '漏洞名称'})
    df = df.drop("CVE", axis=1)
    df = df.drop("CVSS v2.0 Base Score", axis=1)
    df = df.drop("Risk", axis=1)
    df = df.drop("Protocol", axis=1)
    df = df.drop("Synopsis", axis=1)
    df = df.drop("Description", axis=1)
    df = df.drop("Solution", axis=1)
    df = df.drop("See Also", axis=1)
    df['主机'] = df['主机'].astype(str)
    df['端口'] = df['端口'].astype(str)
    num = 1
    list1 = ['Google', 'Runoob']
    for index, row in df.iterrows():
        if "is considered as dead - not scanning" in str(df.loc[index]["Plugin Output"]):
            df.loc[index, "Plugin Output"] = "Down"
            df.loc[index, "序号"] = num
            list1.clear()
            list1.append('0')
        else:
            df.loc[index, "Plugin Output"] = "Up"
            df.loc[index, "序号"] = num
        if df.loc[index, "Plugin Output"] == "Up":
            if num > 1:
                a = df.loc[int(index) - 1, '主机']
                b = df.loc[int(index), '主机']
                if a == b:
                    c = str(df.loc[index, '端口'])
                    d = list1.count(c)
                    if d == 1:
                        df.loc[index, '端口'] = '0'
                    else:
                        e = str(df.loc[index, '端口'])
                        list1.append(e)
                        df.loc[index, '端口'] = '0'
                else:
                    df.loc[index, '端口'] = str(list1)
                    list1.clear()
                    list1.append('0')
        num += 1
    df = df.drop(df[(df['端口'] == str("0")) & (df['Plugin Output'] == 'Up')].index)
    num = 1
    for index, row in df.iterrows():
        df.loc[index, "序号"] = num
        num += 1
    df.to_excel(output_file, index=False)


# 读取CSV文件并输出漏洞XLSX文件
def read_write_csv_vuln(input_file, output_file):
    df = pd.read_csv(input_file)
    df = df.dropna(subset=['Risk'])
    df.to_excel(output_file, index=False)


if __name__ == '__main__':
    # 示例用法
    read_write_csv_xlsx('input.csv', '源文件.xlsx')
    read_write_csv_prot('input.csv', '端口文件.xlsx')
    read_write_csv_vuln('input.csv', '漏洞文件.xlsx')
