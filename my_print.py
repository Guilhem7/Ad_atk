log = lambda x: print(f'\x1b[93;1m[+]\x1b[0m {x}')
warn = lambda x: print(f'\x1b[91;1m[x]\x1b[0m {x}')
success = lambda x: print(f'\x1b[92;1m[+]\x1b[0m {x}')
section = lambda m: print("\n" + '='*80 + "\n" + m.center(80," ") +"\n" + "="*80)
