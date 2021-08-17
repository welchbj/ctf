void execute(const char * cmd) {
    puts("Getting flag:");
    system("cat flag fl*");

    puts("Running command:");
    puts(cmd);
    system(cmd);
}
