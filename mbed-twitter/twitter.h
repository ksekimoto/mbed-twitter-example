/*
 * Copyright (c) 2017 Kentaro Sekimoto
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TWITTER_H_
#define TWITTER_H_

#include "mbed.h"

class Twitter {
public:
    Twitter(NetworkInterface *iface);
    virtual ~Twitter();
    void set_keys(char *cons_key, char *cons_sec, char *accs_key, char *accs_sec);
    void statuses_update(char *str);
private:
    NetworkInterface *_iface;
    char *_cons_key;
    char *_cons_sec;
    char *_accs_key;
    char *_accs_sec;
};

#endif /* TWITTER_H_ */
