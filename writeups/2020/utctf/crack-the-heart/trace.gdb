set pagination off

# Foil simple anti-debugging techniques.
catch syscall ptrace
commands
    silent
    set $rax = 0
    continue
end

# Use this snippet to determine the length of the expected solution.
if (0)
catch syscall read
commands
    silent
    printf "Input read length: %d\n", $rdx
    continue
end
end

# Watch access to .bss segment, which contains the global flag. This
# snippet was used to eventually find the comparison routines that
# lead to our eventual SAT model.
if (0)
rwatch *0x4149b0
commands
     silent
end
end

# Break on xor bl,al to record bl operand.
break *0x4020a7
commands
    silent
    printf "0x%x,", $bl & 0xff
    continue
end

# Break on sub al,bl to record al operand.
break *0x40213b
commands
    silent
    printf "0x%x\n", $al & 0xff
    continue
end

# Run the program with dummy input, filling the maximum read length.
run < <(echo 'utflag{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}') >/dev/null
quit