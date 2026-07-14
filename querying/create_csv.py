import pandas as pd

df = pd.read_excel("21.xlsx")
df.to_csv("21.csv", index=False)