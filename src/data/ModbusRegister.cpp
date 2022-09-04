#include "ModbusRegister.h"
#include "modbus.h"

#include <syslog.h>

void ModbusRegister::exportValue(uint16_t *out) {
    switch (type) {
    case MODBUS_TYPE_UINT16:
        out[0] = value[0];
        break;
    case MODBUS_TYPE_UINT32:
    case MODBUS_TYPE_FLOAT:
    case MODBUS_TYPE_FLOAT_ABCD:
    case MODBUS_TYPE_FLOAT_DCBA:
    case MODBUS_TYPE_FLOAT_BADC:
    case MODBUS_TYPE_FLOAT_CDAB:
        out[0] = value[0];
        out[1] = value[1];
        break;
    case MODBUS_TYPE_DOUBLE:
        out[0] = value[0];
        out[1] = value[1];
        out[2] = value[2];
        out[3] = value[3];
        break;
    default:
        syslog(LOG_ERR, "Invalid register type %d to export value\n", type);
        break;
    }
}

void ModbusRegister::assignValue(uint16_t *in) {
    switch (type) {
    case MODBUS_TYPE_UINT16:
        value[0] = in[0];
        value[1] = 0;
        value[2] = 0;
        value[3] = 0;
        break;
    case MODBUS_TYPE_UINT32:
        value[0] = in[1];
        value[1] = in[0];
        value[2] = 0;
        value[3] = 0;
        break;
    case MODBUS_TYPE_FLOAT:
    case MODBUS_TYPE_FLOAT_ABCD:
    case MODBUS_TYPE_FLOAT_DCBA:
    case MODBUS_TYPE_FLOAT_BADC:
    case MODBUS_TYPE_FLOAT_CDAB:
        value[0] = in[0];
        value[1] = in[1];
        value[2] = 0;
        value[3] = 0;
        break;
    case MODBUS_TYPE_DOUBLE:
        value[0] = in[0];
        value[1] = in[1];
        value[2] = in[2];
        value[3] = in[3];
        break;
    default:
        syslog(LOG_ERR, "Invalid register type %d to assign value\n", type);
        break;
    }
}

void ModbusRegister::assignValue(double val) {
    uint16_t val16[4] = { 0 };
    memset(val16,0,sizeof(val16));

    switch (type) {
    case MODBUS_TYPE_UINT16:
        value[0] = (uint16_t)val;
        value[1] = 0;
        value[2] = 0;
        value[3] = 0;
        break;
    case MODBUS_TYPE_UINT32:
        modbus_set_uint32((uint32_t)val,value);
        value[2] = 0;
        value[3] = 0;
        break;
    case MODBUS_TYPE_FLOAT:
        modbus_set_float((float)val,value);
        value[2] = 0;
        value[3] = 0;
        break;
    case MODBUS_TYPE_FLOAT_ABCD:
        modbus_set_float_abcd((float)val,value);
        value[2] = 0;
        value[3] = 0;
        break;
    case MODBUS_TYPE_FLOAT_DCBA:
        modbus_set_float_dcba((float)val,value);
        value[2] = 0;
        value[3] = 0;
        break;
    case MODBUS_TYPE_FLOAT_BADC:
        modbus_set_float_badc((float)val,value);
        value[2] = 0;
        value[3] = 0;
        break;
    case MODBUS_TYPE_FLOAT_CDAB:
        modbus_set_float_cdab((float)val,value);
        value[2] = 0;
        value[3] = 0;
        break;
    case MODBUS_TYPE_DOUBLE:
        modbus_set_double(val,value);
        break;
    default:
        syslog(LOG_ERR, "Invalid register type %d to assign value\n", type);
        break;
    }
}

const double ModbusRegister::exportValue(void) {
    double output = 0.0;

    switch (type) {
    case MODBUS_TYPE_UINT16:
        output = (double)value[0];
        break;
    case MODBUS_TYPE_UINT32:
        output = (double)modbus_get_uint32(value);
        break;
    case MODBUS_TYPE_FLOAT:
        output = (double)modbus_get_float(value);
        break;
    case MODBUS_TYPE_FLOAT_ABCD:
        output = (double)modbus_get_float_abcd(value);
        break;
    case MODBUS_TYPE_FLOAT_DCBA:
        output = (double)modbus_get_float_dcba(value);
        break;
    case MODBUS_TYPE_FLOAT_BADC:
        output = (double)modbus_get_float_badc(value);
        break;
    case MODBUS_TYPE_FLOAT_CDAB:
        output = (double)modbus_get_float_cdab(value);
        break;
    case MODBUS_TYPE_DOUBLE:
        output = modbus_get_double(value);
        break;
    default:
        syslog(LOG_ERR, "Invalid register type %d to assign value\n", type);
        break;
    }

    return output;
}