from capstone import *
from elftools.elf.elffile import ELFFile
from Registers import Registers
import re

class DisARMPy:
    def __init__(self, filename):
        self.binary = filename
        self.file = open(filename, 'rb')
        self.data = self.file.read()

        self.elfFile = ELFFile(self.file)
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.registers = Registers()

    def disassemble(self):
        textSection = self.elfFile.get_section_by_name('.text')
        textData = textSection.data()
        self.registers.pc = textSection.header['sh_addr']
        
        for idx, i in enumerate(self.md.disasm(textData, self.registers.pc)):
            instruction = i.mnemonic
            options = i.op_str
            
            ilEquiv = self.generateIL(instruction, options)
            
            print('0x{:08x}\t\t{:<10}\t{:<20}\t{:<50}'.format(i.address, instruction, options, ilEquiv))
            
            if idx == 5:
                break
                
    def calculateRegisterSum(self, registers):
        value = 0
        for reg in registers:
            if not reg.startswith('#'):
                value += getattr(self.registers, reg)
            else:
                value += int(reg.replace('#', ''))
        
        return value

    def generateIL(self, instruction, options):
        self.registers.pc += 4
        
        if instruction == 'ldr':
            offset = re.findall('\[([^\]]+)\]', options)
            if len(offset) > 0:
                offset = offset[0]
                offsetList = map(str, offset.replace(' ', '').split(','))
                value = self.calculateRegisterSum(offsetList)
                
                dest = options.replace(offset, '').replace(', []', '')
            else:
                dest = options.split(', ')[0]
                value = getattr(self.registers, options)
                
            setattr(self.registers, dest, value)
            return '{} = 0x{:x}'.format(dest, value)
        
        elif instruction == 'add':
            opts = options.split(', ')
            dest = opts[0]
            value = self.calculateRegisterSum(opts[1:])

            setattr(self.registers, dest, value)
            return '{} = 0x{:x}'.format(dest, value)
                                
        return 'PSUEDO CODE HERE'