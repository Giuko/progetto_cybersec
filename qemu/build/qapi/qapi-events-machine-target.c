/* AUTOMATICALLY GENERATED by qapi-gen.py DO NOT MODIFY */

/*
 * Schema-defined QAPI/QMP events
 *
 * Copyright (c) 2014 Wenchao Xia
 * Copyright (c) 2015-2018 Red Hat Inc.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qapi-emit-events.h"
#include "qapi-events-machine-target.h"
#include "qapi-visit-machine-target.h"
#include "qapi/compat-policy.h"
#include "qapi/error.h"
#include "qobject/qdict.h"
#include "qapi/qmp-event.h"

#if defined(TARGET_S390X) && defined(CONFIG_KVM)
void qapi_event_send_cpu_polarization_change(S390CpuPolarization polarization)
{
    QDict *qmp;
    QObject *obj;
    Visitor *v;
    q_obj_CPU_POLARIZATION_CHANGE_arg param = {
        polarization
    };

    if (compat_policy.unstable_output == COMPAT_POLICY_OUTPUT_HIDE) {
        return;
    }

    qmp = qmp_event_build_dict("CPU_POLARIZATION_CHANGE");

    v = qobject_output_visitor_new_qmp(&obj);

    visit_start_struct(v, "CPU_POLARIZATION_CHANGE", NULL, 0, &error_abort);
    visit_type_q_obj_CPU_POLARIZATION_CHANGE_arg_members(v, &param, &error_abort);
    visit_check_struct(v, &error_abort);
    visit_end_struct(v, NULL);

    visit_complete(v, &obj);
    if (qdict_size(qobject_to(QDict, obj))) {
        qdict_put_obj(qmp, "data", obj);
    } else {
        qobject_unref(obj);
    }
    qapi_event_emit(QAPI_EVENT_CPU_POLARIZATION_CHANGE, qmp);

    visit_free(v);
    qobject_unref(qmp);
}
#endif /* defined(TARGET_S390X) && defined(CONFIG_KVM) */

/* Dummy declaration to prevent empty .o file */
char qapi_dummy_qapi_events_machine_target_c;
