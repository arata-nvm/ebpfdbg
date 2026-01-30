import time
import gdb

# gdb.execute('set debug arch 1')
# gdb.execute('set debug remote 1')
# gdb.execute('set debug xml 1')
# gdb.execute('set debug target 1')

gdb.execute('set debuginfod enabled off')
gdb.execute('target remote :9001')
gdb.execute('b add')
gdb.execute('''commands 1
silent
continue
end
''')

start_time = time.time()
gdb.execute('c')
end_time = time.time()
print(f"Time taken: {end_time - start_time:.3f} seconds")
