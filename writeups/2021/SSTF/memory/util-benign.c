void execute(const char * cmd) {
    puts("Running command:");
    puts(cmd);
    system(cmd);
}
