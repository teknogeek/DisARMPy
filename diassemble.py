from DisARMPy import DisARMPy

def main():
    dis = DisARMPy('lib.so')
    dis.disassemble()

if __name__ == '__main__':
    main()