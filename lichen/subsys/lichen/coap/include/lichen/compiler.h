/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/compiler.h
 * @brief Compiler compatibility macros (nullability annotations, feature detection)
 *
 * Provides portable _Nonnull and _Nullable annotations that expand to
 * nothing on compilers without Clang-style nullability support.
 */

#ifndef LICHEN_COMPILER_H_
#define LICHEN_COMPILER_H_

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#endif /* LICHEN_COMPILER_H_ */
