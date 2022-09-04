#include "DatetimeCommand.h"
#include "Utils.h"

#include <syslog.h>
#include <string.h>

cJSON* DatetimeCommand::execute(const std::string& input, SystemData *data) {
    struct tm tm;
    struct timespec ts;
    cJSON* output = NULL;

    memset(&tm, 0, sizeof(tm));
    memset(&ts, 0, sizeof(ts));

    /*
     * For now, just discard the field not found
     */
    if (sscanf(input.c_str(),"%d-%d-%dT%d:%d:%d",&tm.tm_year,&tm.tm_mon,&tm.tm_mday,
                    &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {

        syslog(LOG_ERR, "Problem capturing 'datetime' value\n");
        output = Utils::buildJsonERROR("datetime",data->cfg->deviceId,"Invalid input field for datetime");
    }
    else {
        /*
         * Sanity checks with datetime
         */
        bool correct = true;
        if ((tm.tm_year < 1900) || (tm.tm_year > 2100)) {
            syslog(LOG_ERR, "Datetime: invalid year field\n");
            output = Utils::buildJsonERROR("datetime",data->cfg->deviceId,"Invalid year in datetime");
            correct = false;
        }
        else {
            tm.tm_year -= 1900;
        }

        if (correct == true) {
            if ((tm.tm_mon < 0) || (tm.tm_mon > 12)) {
                syslog(LOG_ERR, "Datetime: invalid month field\n");
                output = Utils::buildJsonERROR("datetime",data->cfg->deviceId,"Invalid month in datetime");
                correct = false;
            }
        }

        if (correct == true) {
            if ((tm.tm_mday < 0) || (tm.tm_mday > 31)) {
                syslog(LOG_ERR, "Datetime: invalid day field\n");
                output = Utils::buildJsonERROR("datetime",data->cfg->deviceId,"Invalid day in datetime");
                correct = false;
            }
        }

        if (correct == true) {
            if ((tm.tm_hour < 0) || (tm.tm_hour > 23)) {
                syslog(LOG_ERR, "Datetime: invalid hour field\n");
                output = Utils::buildJsonERROR("datetime",data->cfg->deviceId,"Invalid hour in datetime");
                correct = false;
            }
        }

        if (correct == true) {
            if ((tm.tm_min < 0) || (tm.tm_min > 59)) {
                syslog(LOG_ERR, "Datetime: invalid minutes field\n");
                output = Utils::buildJsonERROR("datetime",data->cfg->deviceId,"Invalid minutes in datetime");
                correct = false;
            }
        }

        if (correct == true) {
            if ((tm.tm_sec < 0) || (tm.tm_sec > 59)) {
                syslog(LOG_ERR, "Datetime: invalid seconds field\n");
                output = Utils::buildJsonERROR("datetime",data->cfg->deviceId,"Invalid seconds in datetime");
                correct = false;
            }
        }

        if (correct == true) {            
            ts.tv_sec  = mktime(&tm);
            ts.tv_nsec = 0;
            syslog(LOG_DEBUG, "Setting new datetime: %d-%d-%d %d:%d:%d - %ld\n",
                        tm.tm_year, tm.tm_mon, tm.tm_mday,
                        tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_sec);
            if (clock_settime(CLOCK_REALTIME, &ts) < 0) {
                syslog(LOG_ERR, "Problem clock_settime\n");
                output = Utils::buildJsonERROR("datetime",data->cfg->deviceId,"Problem setting new datetime");
            }
            else {
                output = Utils::buildJsonOK("datetime",data->cfg->deviceId);
            }
        }
    }
    
    return output;
}
