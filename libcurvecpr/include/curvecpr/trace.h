#ifndef __CURVECPR_TRACE_H
#define __CURVECPR_TRACE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>

enum curvecpr_trace_level {
    CURVECPR_TRACE_LEVEL_DEBUG, CURVECPR_TRACE_LEVEL_INFO, CURVECPR_TRACE_LEVEL_WARNING, CURVECPR_TRACE_LEVEL_ERROR
};

void curvecpr_trace_enable (enum curvecpr_trace_level level);
void curvecpr_trace_disable (void);
void curvecpr_trace_set_callback (void (*callback)(enum curvecpr_trace_level level, const char *file, int line, const char *func, const char *format, va_list args));

static inline void curvecpr_trace_noop_cb (enum curvecpr_trace_level level, const char *file, int line, const char *func, const char *format, va_list args)
{
    /* Do nothing. */
}
void curvecpr_trace_stderr_cb (enum curvecpr_trace_level level, const char *file, int line, const char *func, const char *format, va_list args);

void curvecpr_trace (enum curvecpr_trace_level level, const char *file, int line, const char *func, const char *format, ...);
#define CURVECPR_TRACE(level, ...) curvecpr_trace((level), __FILE__, __LINE__, __func__, __VA_ARGS__)
#define CURVECPR_TRACE_DEBUG(...) CURVECPR_TRACE(CURVECPR_TRACE_LEVEL_DEBUG, __VA_ARGS__)
#define CURVECPR_TRACE_INFO(...) CURVECPR_TRACE(CURVECPR_TRACE_LEVEL_INFO, __VA_ARGS__)
#define CURVECPR_TRACE_WARNING(...) CURVECPR_TRACE(CURVECPR_TRACE_LEVEL_WARNING, __VA_ARGS__)
#define CURVECPR_TRACE_ERROR(...) CURVECPR_TRACE(CURVECPR_TRACE_LEVEL_ERROR, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
