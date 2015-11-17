/*
 * kcompat.h
 *
 *  Created on: Jun 24, 2015
 *      Author: leeopop
 */

#ifndef DRIVERS_NET_MLNX_UIO_INCLUDE_KCOMPAT_H_
#define DRIVERS_NET_MLNX_UIO_INCLUDE_KCOMPAT_H_


void register_module_parameter(__module_param_t* param_t);


void register_module_parameter_desc(__module_param_t* param_t, const char* desc);


int module_paramter_count();


enum module_param_type module_paramter_type(int index);


void* module_paramter_ptr(int index);


const char* module_paramter_name(int index);


const char* module_paramter_desc(int index);


int module_parameter_elt_count(int index);


#endif /* DRIVERS_NET_MLNX_UIO_INCLUDE_KCOMPAT_H_ */
