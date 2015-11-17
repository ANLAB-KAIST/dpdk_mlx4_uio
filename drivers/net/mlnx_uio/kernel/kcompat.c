/*
 * kcompat.c
 *
 *  Created on: Jun 24, 2015
 *      Author: leeopop
 */

#include "kmod.h"

static struct list_head __module_parameter_list = LIST_HEAD_INIT(__module_parameter_list);
void register_module_parameter(__module_param_t* param_t)
{
	list_add_tail(&param_t->list, &__module_parameter_list);
}

void register_module_parameter_desc(__module_param_t* param_t, const char* desc)
{
	param_t->description = desc;
}

int module_paramter_count()
{
	int count = 0;
	__module_param_t* iter = 0;
	list_for_each_entry(iter, &__module_parameter_list, list)
	{
		count++;
	}
	return count;
}

enum module_param_type module_paramter_type(int index)
{
	int count = 0;
	__module_param_t* iter = 0;
	list_for_each_entry(iter, &__module_parameter_list, list)
	{
		if(count == index)
			return iter->param_type;
		count++;
	}
	return param_type_none;
}

void* module_paramter_ptr(int index)
{
	int count = 0;
	__module_param_t* iter = 0;
	list_for_each_entry(iter, &__module_parameter_list, list)
	{
		if(count == index)
			return iter->ptr;
		count++;
	}
	return 0;
}

const char* module_paramter_name(int index)
{
	int count = 0;
	__module_param_t* iter = 0;
	list_for_each_entry(iter, &__module_parameter_list, list)
	{
		if(count == index)
			return iter->name;
		count++;
	}
	return 0;
}

const char* module_paramter_desc(int index)
{
	int count = 0;
	__module_param_t* iter = 0;
	list_for_each_entry(iter, &__module_parameter_list, list)
	{
		if(count == index)
			return iter->description;
		count++;
	}
	return 0;
}

int module_parameter_elt_count(int index)
{
	int count = 0;
	__module_param_t* iter = 0;
	list_for_each_entry(iter, &__module_parameter_list, list)
	{
		if(count == index)
			return iter->ptr_size / iter->elt_size;
		count++;
	}
	return 0;
}

