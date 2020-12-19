// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// 
// CoreSTL
// 
// Copyright (C) MeeSong. All rights reserved.
// 	    Author : MeeSong 
//	    Email  : meesong@live.cn
// 	    Github : https://github.com/meesong
//      License: GNU Library General Public License(LGPL) - Version 3
// 
// This file is part of Idea
// 
// Idea is free software; you can redistribute it and/or modify
// it under the terms of the GNU Library General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Idea is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Library General Public License for more details.
//
// You should have received a copy of the GNU Library General Public License
// along with Idea.  If not, see <http://www.gnu.org/licenses/>.
//
// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

#pragma once


/* Byte swap*/
#ifndef ByteSwap16$
#define ByteSwap16$(x) (                    \
    ((unsigned __int16(x) & unsigned __int16(0xFF << 8)) >> 8) |      \
    ((unsigned __int16(x) & unsigned __int16(0xFF >> 0)) << 8)        \
)
#endif

#ifndef ByteSwap32$
#define ByteSwap32$(x) (                    \
    ((unsigned __int32(x) & unsigned __int32(0xFF << 24)) >> 24) |    \
    ((unsigned __int32(x) & unsigned __int32(0xFF << 16)) >>  8) |    \
    ((unsigned __int32(x) & unsigned __int32(0xFF <<  8)) <<  8) |    \
    ((unsigned __int32(x) & unsigned __int32(0xFF <<  0)) << 24)      \
)
#endif

#ifndef ByteSwap64$
#define ByteSwap64$(x) (                    \
    ((unsigned __int64(x) & unsigned __int64(0xFF << 56)) >> 56) |    \
    ((unsigned __int64(x) & unsigned __int64(0xFF << 48)) >> 40) |    \
    ((unsigned __int64(x) & unsigned __int64(0xFF << 40)) >> 24) |    \
    ((unsigned __int64(x) & unsigned __int64(0xFF << 32)) >>  8) |    \
    ((unsigned __int64(x) & unsigned __int64(0xFF << 24)) <<  8) |    \
    ((unsigned __int64(x) & unsigned __int64(0xFF << 16)) << 24) |    \
    ((unsigned __int64(x) & unsigned __int64(0xFF <<  8)) << 40) |    \
    ((unsigned __int64(x) & unsigned __int64(0xFF <<  0)) << 56) |    \
)
#endif
