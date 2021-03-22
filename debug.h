
// level 0 is no messages, level 3 is most messages
void debug_init(int level, int show_elapsed_time, int show_relative_time, int show_file_and_line);

void _die(const char *filename, const int linenumber, const char *format, ...);
void _warn(const char *filename, const int linenumber, const char *format, ...);
void _inform(const char *filename, const int linenumber, const char *format, ...);
void _debug(const char *filename, const int linenumber, int level, const char *format, ...);

#define die(...) _die(__FILE__, __LINE__, __VA_ARGS__)
#define debug(...) _debug(__FILE__, __LINE__, __VA_ARGS__)
#define warn(...) _warn(__FILE__, __LINE__, __VA_ARGS__)
#define inform(...) _inform(__FILE__, __LINE__, __VA_ARGS__)
