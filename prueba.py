python -c "
import re, open as o
txt = open(r'C:\z_upm\apl02\tester.py', encoding='utf-8').read()
idx = txt.find('dlltool')
print(txt[max(0,idx-200):idx+400])
"