#include "mypeview.h"

#define VNAME(name) (#name) //打印变量名称
#define PRINT_STRUCT_ONE_INT(structname, subname)\
  do{\
    printf("\t%-10s\t\t%X\n", VNAME(subname), structname->subname);\
  }while(0)

/***************************
 * 注意:malloc之后,不free可能导致
 *      "malloc(): corrupted top size"
 * 不考虑加壳问题
 * 32位PE程序,64位未考虑
 * 
 ************************/
void print_dos_header(IMAGE_DOS_HEADER *dos_header);
void print_nt_header(IMAGE_NT_HEADERS *nt_header);
void print_data_directory(IAMGE_DATA_DIRECTORY *data_directory);
void print_section_header(IAMGE_SECTION_HEADER *section_header);
void print_import_descriptor(IMAGE_IMPORT_DESCRIPTOR *import_descritor);
void print_import_more_descriptor(IMAGE_IMPORT_DESCRIPTOR *import_descritor, FILE *fp_pe_file,\
                                int number_of_sections, IAMGE_SECTION_HEADER *sectionheader);
void print_import_INT(uint32_t rwa_one_INT, FILE *fp);
void print_export_table(IMAGE_EXPORT_DIRECTORY *export_table);
void print_export_more_table(IMAGE_EXPORT_DIRECTORY *export_table, FILE *fp_pe_file,\
                                int number_of_sections, IAMGE_SECTION_HEADER *sectionheader);

uint32_t rva2raw(uint32_t rva, int number_of_sections,IAMGE_SECTION_HEADER *section_header);
int get_numbers_import_table(long offset_import_table, FILE *fp_pe_file);
int get_numbers_of_INT(uint32_t raw_INT, FILE *fp);

int main(int argc, char *argv[])
{
    if (argc < 2) 
    {
        printf ("Help: %s FileName\n", argv[0]);
        exit (EXIT_FAILURE);
    }

    FILE *fp_pe_file = fopen(argv[1], "rb");
    if (!fp_pe_file)
    {
        fprintf (stderr, "打开文件失败\n");
        exit (EXIT_FAILURE);
    }

    //DOS头读取
    IMAGE_DOS_HEADER dos_header;    
    fread(&dos_header, 1, sizeof(IMAGE_DOS_HEADER), fp_pe_file);
    if (dos_header.e_magic != 0x5A4D)
    {
        fprintf (stderr, "请确定该文件是PE文件\n");
        exit (EXIT_FAILURE);
    }
    print_dos_header(&dos_header);
    //NT头读取
    IMAGE_NT_HEADERS nt_header; 
    fseek(fp_pe_file, dos_header.e_lfnew, 0);
    fread(&nt_header, 1, sizeof(IMAGE_NT_HEADERS), fp_pe_file);
    if (nt_header.signature != 0x4550)  //PE标志 50 45 00 00
    {
        fprintf (stderr, "请确定该文件是PE文件\n");
        exit (EXIT_FAILURE);
    }
    if (nt_header.optional_header.magic == 0x20B)
    {
        fprintf (stderr, "不支持64位\n");
        exit (EXIT_SUCCESS);
    }
    
    print_nt_header(&nt_header);

    //section header    由 nt头.file.number_of_sections 决定数量
    int numbers_of_sections = nt_header.file_header.number_of_sections;   //节区的数量
    IAMGE_SECTION_HEADER *p_sections_header;
    p_sections_header = (IAMGE_SECTION_HEADER *)malloc(sizeof(IAMGE_SECTION_HEADER) * numbers_of_sections);
    if (!p_sections_header)
    {
        fprintf (stderr, "内存分配错误\n");
        exit (EXIT_FAILURE);
    }
    fread(p_sections_header, 1, sizeof(IAMGE_SECTION_HEADER)*numbers_of_sections, fp_pe_file);
    for (int i = 0; i < numbers_of_sections; i++)
    {
        print_section_header(&(p_sections_header[i]));
    }
    
    //导入表
    if (nt_header.optional_header.data_directory[1].virtual_address == 0)
    {
        printf("----IMPORT TABLE -----\n");
        printf("NULL\n");
    }else{
        uint32_t offset_import_table;
        IMAGE_IMPORT_DESCRIPTOR *p_import_table;
        int numbers_import_table;   //导入表并不确定,需要自己查看

        offset_import_table = rva2raw(nt_header.optional_header.data_directory[1].virtual_address,\
                            nt_header.file_header.number_of_sections,\
                            p_sections_header);   
        numbers_import_table = get_numbers_import_table(offset_import_table, fp_pe_file);
        p_import_table = (IMAGE_IMPORT_DESCRIPTOR *)malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR) * numbers_import_table);
        fseek(fp_pe_file, offset_import_table, 0);
        fread(p_import_table, numbers_import_table, sizeof(IMAGE_IMPORT_DESCRIPTOR), fp_pe_file);
        for (int i = 0; i < numbers_import_table; i++)
        {
            print_import_descriptor(&p_import_table[i]);
            print_import_more_descriptor(&p_import_table[i], fp_pe_file, numbers_of_sections, p_sections_header);
            printf("\n");
        }

    }
    
    //导出表
    if (nt_header.optional_header.data_directory[0].virtual_address == 0)
    {
        printf("----EXPORT TABLE -----\n");
        printf("NULL\n");
    }else
    {
        uint32_t offset_export_table;
        IMAGE_EXPORT_DIRECTORY export_table;    //因为导出表只有一个,所以直接读取即可

         offset_export_table = rva2raw(nt_header.optional_header.data_directory[0].virtual_address,\
                            nt_header.file_header.number_of_sections,\
                            p_sections_header);
        fseek(fp_pe_file, offset_export_table, 0);
        fread(&export_table, 1, sizeof(IMAGE_EXPORT_DIRECTORY), fp_pe_file);
        print_export_table(&export_table);
        print_export_more_table(&export_table, fp_pe_file, numbers_of_sections, p_sections_header);
    }
    
    free(p_sections_header);
    fclose(fp_pe_file);
    return 0;
}

void print_dos_header(IMAGE_DOS_HEADER *dos_header)
{
    printf("%s:\n", VNAME(DOS_HEADER));
    PRINT_STRUCT_ONE_INT(dos_header, e_magic);
    PRINT_STRUCT_ONE_INT(dos_header, e_lfnew);
}
void print_nt_header(IMAGE_NT_HEADERS *nt_header)
{
    printf("%s:\n", VNAME(NT_HEADER));
    PRINT_STRUCT_ONE_INT(nt_header, signature);
    
    //nt.file_header
    printf("%s\n", VNAME(NT_FILE_HEADER));
    PRINT_STRUCT_ONE_INT(nt_header, file_header.machine);
    PRINT_STRUCT_ONE_INT(nt_header, file_header.number_of_sections);
    PRINT_STRUCT_ONE_INT(nt_header, file_header.time_date_stamp);
    PRINT_STRUCT_ONE_INT(nt_header, file_header.size_of_optional_header);
    PRINT_STRUCT_ONE_INT(nt_header, file_header.characteristics);

    //nt.optional_header
    printf("%s:\n", VNAME(NT_OPTIONAL_HEADER));
    PRINT_STRUCT_ONE_INT(nt_header, optional_header.magic);
    PRINT_STRUCT_ONE_INT(nt_header, optional_header.address_of_entry_point);
    PRINT_STRUCT_ONE_INT(nt_header, optional_header.image_base);
    PRINT_STRUCT_ONE_INT(nt_header, optional_header.section_alignment);
    PRINT_STRUCT_ONE_INT(nt_header, optional_header.file_alignment);
    PRINT_STRUCT_ONE_INT(nt_header, optional_header.size_of_image);
    PRINT_STRUCT_ONE_INT(nt_header, optional_header.size_of_headers);
    PRINT_STRUCT_ONE_INT(nt_header, optional_header.subsystem);    PRINT_STRUCT_ONE_INT(nt_header, optional_header.magic);
    PRINT_STRUCT_ONE_INT(nt_header, optional_header.number_of_rva_and_sizes);
    
    //nt.optional_header.data_directory
    print_data_directory(nt_header->optional_header.data_directory);
    
}
void print_data_directory(IAMGE_DATA_DIRECTORY *data_directory)
{
    printf("%s:\n", VNAME(DATA_DIRECTORY));
    printf("  %s:\n", VNAME(export_directory));
    PRINT_STRUCT_ONE_INT(data_directory, virtual_address);
    PRINT_STRUCT_ONE_INT(data_directory, size);

    /*****************
    注意: 
    data_directory +=  1 相当于指针直接偏移一个sizeof(type)字节量
    不是偏移一个字节 不能写成 
    data_directory += sizeof(IAMGE_DATA_DIRECTORY) * 1;
    *****************/
    data_directory +=  1;       
    printf("  %s:\n", VNAME(import_directory));
    PRINT_STRUCT_ONE_INT(data_directory, virtual_address);
    PRINT_STRUCT_ONE_INT(data_directory, size);

    data_directory += 1;
    printf("  %s:\n", VNAME(resource_directory));
    PRINT_STRUCT_ONE_INT(data_directory, virtual_address);
    PRINT_STRUCT_ONE_INT(data_directory, size);

    data_directory += 7;
    printf("  %s:\n", VNAME(TLS_directory));
    PRINT_STRUCT_ONE_INT(data_directory, virtual_address);
    PRINT_STRUCT_ONE_INT(data_directory, size);
}
void print_section_header(IAMGE_SECTION_HEADER *section_header)
{
    printf("%s:\t", VNAME(SECTION_HEADER));
    for (int i = 0; i < 8; i++)
    {
        printf("%c", section_header->name[i]);
    }
    printf("\n");
    PRINT_STRUCT_ONE_INT(section_header, Misc.virtual_size);
    PRINT_STRUCT_ONE_INT(section_header, virtual_address);
    PRINT_STRUCT_ONE_INT(section_header, size_of_raw_data);
    PRINT_STRUCT_ONE_INT(section_header, pointer_to_raw_data);
    PRINT_STRUCT_ONE_INT(section_header, characteristics);

}
uint32_t rva2raw(uint32_t rva, int number_of_sections,IAMGE_SECTION_HEADER *section_header)
{
    int location;   //RVA在哪个节区,这里按各个节区本身按地址顺序排列        (猜测,不确定,如果不是,则需要重新修改代码)
    for ( location = 0; rva < section_header[location].virtual_address && location < number_of_sections; location++)
        continue;
    if (location == number_of_sections)
    {
        fprintf (stderr, "RVA转RAW错误, RVA值过小\n");
        exit (EXIT_FAILURE); 
    }
      
    return (rva-section_header[location].virtual_address) + section_header[location].pointer_to_raw_data;
}
int get_numbers_import_table(long offset_import_table, FILE *fp_pe_file)
{
    fseek(fp_pe_file, offset_import_table, 0);  //将文件指针偏移到导入表位置

    int numbers;
    IMAGE_IMPORT_DESCRIPTOR test_import;

    //输入表的 INT address 必定不等于0,以此判断输入表数量
    fread(&test_import, 1, sizeof(IMAGE_IMPORT_DESCRIPTOR), fp_pe_file);
    for (numbers = 0; test_import.original_first_thunk != 0; numbers++)
    {
        fread(&test_import, 1, sizeof(IMAGE_IMPORT_DESCRIPTOR), fp_pe_file);
    }
    return numbers;
}
void print_import_descriptor(IMAGE_IMPORT_DESCRIPTOR *import_descritor)
{
    printf("------import table------\n");
    printf("%s\n", VNAME(IMPORT_DESCRIPTOR));
    PRINT_STRUCT_ONE_INT(import_descritor, name);
    PRINT_STRUCT_ONE_INT(import_descritor, original_first_thunk);
    PRINT_STRUCT_ONE_INT(import_descritor, first_thunk);
}
void print_import_more_descriptor(IMAGE_IMPORT_DESCRIPTOR *import_descritor, FILE *fp_pe_file,\
                                int number_of_sections, IAMGE_SECTION_HEADER *p_section_header)
{
    char string[100];

    fseek(fp_pe_file, rva2raw(import_descritor->name, number_of_sections, p_section_header), 0);
    fread(string, 1, 100, fp_pe_file);
    printf("DLL name:\t%s\n", string);

    int number_of_INT;
    uint32_t *address_of_INT;   //INT地址数组

    number_of_INT =  get_numbers_of_INT(\
                    rva2raw(import_descritor->original_first_thunk, number_of_sections, p_section_header),\
                    fp_pe_file);
    address_of_INT = (uint32_t *)malloc(sizeof(uint32_t) * number_of_INT);

    fseek(fp_pe_file, rva2raw(import_descritor->original_first_thunk, number_of_sections, p_section_header), 0);
    fread(address_of_INT, number_of_INT, sizeof(uint32_t), fp_pe_file);
    for (int i = 0; i < number_of_INT; i++)
    {
        print_import_INT(rva2raw(address_of_INT[i], number_of_sections, p_section_header), fp_pe_file);
    }
    free(address_of_INT);
}
int get_numbers_of_INT(uint32_t raw_INT, FILE *fp)
{
    //和得到导入表数量相似,使用地址为0作为边界条件判断数量
    uint32_t address;
    int numbers;

    fseek(fp, raw_INT, 0);
    fread(&address, 1, sizeof(address), fp);
    for (numbers = 0; address != 0; numbers++)
    {
        fread(&address, 1, sizeof(address), fp);
    }
    return numbers;    
}
void print_import_INT(uint32_t raw_one_INT, FILE *fp)
{
    uint16_t hint;
    char name[100];

    fseek(fp, raw_one_INT, 0);
    fread(&hint, 1, sizeof(uint16_t), fp);
    fread(name, 1, 100, fp);
    printf("\t%s\t%X\n", VNAME(INT.hint), hint);
    printf("\t%s\t%s\n",VNAME(name), name);
}
void print_export_table(IMAGE_EXPORT_DIRECTORY *export_table)
{
    printf("------export table------\n");
    PRINT_STRUCT_ONE_INT(export_table, time_date_stamp);
    PRINT_STRUCT_ONE_INT(export_table, name);
    PRINT_STRUCT_ONE_INT(export_table, number_of_functions);
    PRINT_STRUCT_ONE_INT(export_table, number_of_names);
    PRINT_STRUCT_ONE_INT(export_table, address_of_functions);
    PRINT_STRUCT_ONE_INT(export_table, address_of_names);
    PRINT_STRUCT_ONE_INT(export_table, address_of_name_ordinals);

}
void print_export_more_table(IMAGE_EXPORT_DIRECTORY *export_table, FILE *fp,\
                                int number_of_sections, IAMGE_SECTION_HEADER *sectionheader)
{
    //打印 库文件名
    char dll_name[100];
    fseek(fp, rva2raw(export_table->name, number_of_sections, sectionheader), 0);
    fread(dll_name, 1, 100, fp);
    printf("%s:\t%s\n", VNAME(name), dll_name);

    //打印 address of funtions
    uint32_t address_of_function;
    printf("functions:\n");
    printf("\t\tRVA\t\tRAW\n");
    fseek(fp, rva2raw(export_table->address_of_functions, number_of_sections, sectionheader), 0);
    fread(&address_of_function, 1, sizeof(address_of_function), fp);
    for (int i = 0; i < export_table->number_of_functions; i++)
    {
        printf("\t\t%d\t\t%d\n", address_of_function, rva2raw(address_of_function,\
                number_of_sections, sectionheader));
    }

    //打印name of functions
    uint32_t *address_of_name;  //存储 name(数组) 地址
    char function_name[100];    //不定长打印.最大100字节,可能越界
  
    printf("names:\n");
    printf("\tindex\tname\n");
    address_of_name = (uint32_t *)malloc(sizeof(uint32_t) * export_table->number_of_names);
    fseek(fp, rva2raw(export_table->address_of_names, number_of_sections, sectionheader), 0);
    fread(address_of_name, export_table->number_of_names, sizeof(address_of_name), fp);
    for (int i = 0; i < export_table->number_of_names; i++)
    {
        fseek(fp, rva2raw(address_of_name[i], number_of_sections, sectionheader), 0);
        fread(function_name, 1, 100, fp);
        printf("\t%d\t%s\n", i, function_name);
    }
   free(address_of_name);
    //打印 ordinal(元素大小2字节)
    uint16_t *address_of_ordinal;   

    printf("ordinals\n");
    printf("\tindex\tordinal\n");
    address_of_ordinal = (uint16_t *)malloc(sizeof(uint16_t) * export_table->number_of_names);
    fseek(fp, rva2raw(export_table->address_of_name_ordinals, number_of_sections, sectionheader), 0);
    fread(address_of_ordinal, export_table->number_of_names, sizeof(address_of_ordinal), fp);
    for (int i = 0; i < export_table->number_of_names; i++)
    {
        printf("\t%d\t%d\n", i, address_of_ordinal[i]);
    }
    free(address_of_ordinal);
    
}