import time
import gdb

gdb.execute('set debuginfod enabled off')
gdb.execute('target remote :9001')
gdb.execute('catch syscall getpid')
gdb.execute('''commands 1
silent
continue
end
''')

start_time = time.time()
gdb.execute('c')
end_time = time.time()
print(f"Time taken: {end_time - start_time:.3f} seconds")
