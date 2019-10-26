#ifndef _MYPEVIEW_H
#define _MYPEVIEW_H

#include<stdio.h>
#include<stdint.h>
#include <stdlib.h>
/*******************
实现peview, 不考虑加壳, 仅32bits系统
注意: 使用小端标记法


*******************/

//Dos头
typedef struct _IMAGE_DOS_HEADER{
    uint16_t e_magic;  //Dos Signature : 4D5A ("MZ")  
    uint16_t  unknow[29];
    uint32_t e_lfnew; //NT头偏移量

} IMAGE_DOS_HEADER; //一共64(40h)字节大小

/*****************
struct _DOS存根
{
    大小不定, 位于      40h ~ IMAGE_DOS_HEAER.e_lfnew-1       范围内
    为使dos环境运行
};
******************/

//NT头
typedef struct _IMAGE_FILE_HEADER{
    uint16_t machine;    //机器码,标识cpu架构? Intel x86 Cpu 为 14C
    uint16_t number_of_sections; //节区数量,必须大于0, 该值与实际节区数目不同时,将出错
    uint32_t time_date_stamp;   //时间戳,编译器提供,但delphi未提供,此值不可信
    uint32_t unknow[2];
    uint16_t size_of_optional_header;   //IMAGE_OPTIONAL_HEADER大小,虽然c编写时固定,但装载器需要以此判断32位还是64位
    uint16_t characteristics;   //属性标识文件是可执行,dll
} IMAGE_FILE_HEADER;    //包含于IAMGE_NT_HEADERS
typedef struct _IMAGE_DATA_DIRECTORY{
    uint32_t virtual_address;
    uint32_t size;
} IAMGE_DATA_DIRECTORY;  //包含于IMAGE_OPTIONAL_HEADER
typedef struct _IMAGE_OPTIONAL_HEADER
{
    uint16_t magic; //32位010B 64位020B
    uint8_t unknown_1[2];
    uint32_t unknown_2[3];
    uint32_t address_of_entry_point;    //EP的RVA值,即程序执行的最初地址
    uint32_t unknown_3[2];
    uint32_t image_base;    //文件的优先装入地址    执行pe时,先创建进程,再将文件载入内存,最后将EIP寄存器值设置为 imagebase+address_of_entry_point
    uint32_t section_alignment; //节区在内存中的最小单位
    uint32_t file_alignment;    //节区在磁盘中最小单位
    uint16_t unknown_4[6];
    uint32_t unknown_5;
    uint32_t size_of_image; //指定PE Image在虚拟内存所占空间大小
    uint32_t size_of_headers;   //整个PE头大小  必须是file_alignment大小的整数倍 第一节区所在位置(磁盘) = 文件开始 + 此值
    uint32_t unknown_6;
    uint16_t subsystem; //区分 sys, exe, dll 文件
    uint16_t unknown_7;
    uint32_t unknown_8[5];
    uint32_t number_of_rva_and_sizes;   //装载器通过此值查看data_directory的大小,虽然其大小已固定,但实际未必
    IAMGE_DATA_DIRECTORY data_directory[16];    //其中包含导入,导出,资源,TLS (every * 2)
} IMAGE_OPTIONAL_HEADER;    //包含于IAMGE_NT_HEADERS
typedef struct _IMAGE_NT_HEADERS
{
    uint32_t signature;  //PE Signature: 50 45 00 00 ("PE"00H)
    IMAGE_FILE_HEADER file_header;
    IMAGE_OPTIONAL_HEADER optional_header;
} IMAGE_NT_HEADERS; //NT头

//节区头    数量由 NT头.文件头.number_of_sections 定义 紧接NT头
typedef struct _IMAGE_SECTION_HEADER{
    uint8_t name[8]; //image_size_of_name 可以放入任何值 没有规定使用'\0'结束,也没有规定必须ascii字符,可填入任何值
    union
    {
        uint32_t unknown_1;
        uint32_t virtual_size;  //内存中节区所占大小 
    } Misc;
    uint32_t virtual_address;   //内存中节区起始地址 不带任何值 当加载时由 IMAGE_OPTIONAL_HEADER.section_alignment 大小确定
    uint32_t size_of_raw_data;  //磁盘中节区所占大小
    uint32_t pointer_to_raw_data;   //磁盘中文件起始地址 不带任何值 当加载时由 IMAGE_OPTIONAL_HEADER.file_alignment 大小确定
    uint32_t unknown_2[2];
    uint16_t unknown_3[2];
    uint32_t characteristics;   //节区属性 (bit OR)
} IAMGE_SECTION_HEADER;

//IAT 导入表  NT头.IMAGE_OPTIONAL_HEADER.data_directory[1].virtual_address 指向 IAT位置(RVA值)
//程序导入多少库就拥有多少 IMAGE_IMPORT_DESCRIPTOR
/***************************************
typedef struct _IMAGE_IMPORT_BY_NAME {
    uint16_t hint;  //ordinal
    //uint8_t name[1];    //函数名称(string) 大小未知,直接%s即可,因为以NULL结尾 
    char *name;
} IMAGE_IMPORT_BY_NAME;//需要动态读取
***************************************/
typedef struct _IMAGE_IMPORT_DESCRIPTOR{
    union {
        uint32_t unknown_1;
        uint32_t original_first_thunk;  //INT(import name table) address(RVA) 指向 IMAGE_IMPORT_BY_NAME 结构体的地址
    };
    uint32_t unknown_2[2];
    uint32_t name;  //库名称字符串地址(RVA)
    uint32_t first_thunk;   //IAT(import address table) address(RVA) PE装载器填入该值
} IMAGE_IMPORT_DESCRIPTOR;

//EAT 导出表 NT头.IMAGE_OPTIONAL_HEADER.data_directory[0].virtual_address 指向 IAT位置(RVA值)
//程序只有一个导出表
typedef struct _IMAGE_EXPORT_TABLE{
    uint32_t unknown_1;
    uint32_t time_date_stamp;   //创建时间戳
    uint16_t unknown_2[2]; 
    uint32_t name;  //库文件名称地址
    uint32_t number_of_functions;   //实际导出函数个数
    uint32_t number_of_names;   //导出函数具有名称个数
    uint32_t address_of_functions;  //导出函数地址 个数 == number_of_functions
    uint32_t address_of_names;  //函数名称地址 个数 == number_of_names  4字节
    uint32_t address_of_name_ordinals;  //ordinal地址 个数 == number_of_names 2字节
} IMAGE_EXPORT_DIRECTORY;

#endif