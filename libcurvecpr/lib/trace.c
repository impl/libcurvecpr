#include "config.h"

#include <curvecpr/trace.h>
#include <curvecpr/util.h>

#include <stdarg.h>
#include <stdio.h>

static const char *trace_level_strs[] = { "DEBUG", "INFO", "WARNING", "ERROR" };

static int trace_enabled = 0;
static enum curvecpr_trace_level trace_level = CURVECPR_TRACE_LEVEL_INFO;
static void (*trace_callback)(enum curvecpr_trace_level level, const char *file, int line, const char *func, const char *format, va_list args) = curvecpr_trace_noop_cb;

void curvecpr_trace_enable (enum curvecpr_trace_level level)
{
    trace_enabled = 1;
    trace_level = level;
}

void curvecpr_trace_disable (void)
{
    trace_enabled = 0;
}

void curvecpr_trace_set_callback (void (*callback)(enum curvecpr_trace_level level, const char *file, int line, const char *func, const char *format, va_list args))
{
    trace_callback = callback;
}

void curvecpr_trace_stderr_cb (enum curvecpr_trace_level level, const char *file, int line, const char *func, const char *format, va_list args)
{
    long long trace_time = curvecpr_util_nanoseconds();

    fprintf(stderr, "%0lld %06lld %-7s %s (%s:%d): ", trace_time / 1000000, trace_time % 1000000, trace_level_strs[level], func, file, line);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
}

void curvecpr_trace (enum curvecpr_trace_level level, const char *file, int line, const char *func, const char *format, ...)
{
    if (trace_enabled && level >= trace_level) {
        va_list args;
        va_start(args, format);
        trace_callback(level, file, line, func, format, args);
        va_end(args);
    }
}
