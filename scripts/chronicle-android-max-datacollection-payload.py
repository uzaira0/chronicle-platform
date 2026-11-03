#!/usr/bin/env python3
"""Generate the Android max-dogfood DataCollection study setting payload.

The payload enables every currently active Android collection module that has a
mobile implementation surface. Modules that are enforced by Android's
CollectionStateMachine ACK gate are marked required; operational/shared-device
modules that are not ACK-gated are enabled but optional because the Android app
does not treat them as enrollment/data-sharing consent decisions.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import OrderedDict


MODEL_CLASS = "com.openlattice.chronicle.collection.AndroidDataCollectionSetting"
CURRENT_VERSION = 2

ACK_GATED_MODULES = (
    "usage_events",
    "device_lifecycle",
    "battery_telemetry",
    "interaction_events",
    "in_app_activity_class",
    "audio_activity",
    "audio_content",
    "notification_activity",
    "sleep",
    "activity_recognition",
    "health_connect",
    "connectivity_state",
    "app_network_usage",
    "device_settings",
    "sensor_accelerometer",
    "sensor_light",
    "sensor_proximity",
    "sensor_screen_orientation",
    "sensor_step_counter",
    "sensor_gyroscope",
    "sensor_magnetometer",
    "sensor_gravity",
    "sensor_linear_acceleration",
    "sensor_rotation_vector",
    "sensor_significant_motion",
    "sensor_tilt_detector",
)

NON_GATED_ENABLED_MODULES = (
    "upload_telemetry",
    "sensor_availability",
    "questionnaire",
    "user_identification",
)

SENSOR_TYPES = {
    "sensor_accelerometer": "accelerometer",
    "sensor_light": "light",
    "sensor_proximity": "proximity",
    "sensor_screen_orientation": "screenOrientation",
    "sensor_step_counter": "stepCounter",
    "sensor_gyroscope": "gyroscope",
    "sensor_magnetometer": "magnetometer",
    "sensor_gravity": "gravity",
    "sensor_linear_acceleration": "linearAcceleration",
    "sensor_rotation_vector": "rotationVector",
    "sensor_significant_motion": "significantMotion",
    "sensor_tilt_detector": "tiltDetector",
}


def module_setting(module_id: str, required: bool) -> OrderedDict:
    setting = OrderedDict(
        (
            ("enabled", True),
            ("required", required),
            ("collectionCadence", OrderedDict((("intervalSeconds", 900), ("jitterSeconds", 0)))),
        )
    )

    sensor_type = SENSOR_TYPES.get(module_id)
    if sensor_type is not None:
        setting["sensorPolicy"] = OrderedDict(
            (
                ("@class", "com.openlattice.chronicle.android.AndroidSensorSetting"),
                ("sensors", [sensor_type]),
                ("samplingRateHz", 5),
                ("dutyCycleActiveSeconds", 30),
                ("dutyCyclePeriodSeconds", 300),
            )
        )

    if module_id == "interaction_events":
        setting["interactionPolicy"] = OrderedDict(
            (
                ("gridRows", 6),
                ("gridCols", 4),
                ("captureClicks", True),
                ("captureScrolls", True),
                ("captureElementPosition", True),
            )
        )

    return setting


def build_payload(version: int) -> OrderedDict:
    modules = OrderedDict()
    for module_id in ACK_GATED_MODULES:
        modules[module_id] = module_setting(module_id, required=True)
    for module_id in NON_GATED_ENABLED_MODULES:
        modules[module_id] = module_setting(module_id, required=False)

    return OrderedDict(
        (
            ("@class", MODEL_CLASS),
            ("modules", modules),
            ("version", version),
        )
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate Android max-dogfood DataCollection settings JSON.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="print formatted JSON instead of compact JSON",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="print a short summary to stderr",
    )
    parser.add_argument(
        "--version",
        type=int,
        default=CURRENT_VERSION,
        help=f"DataCollection schema version to emit; default: {CURRENT_VERSION}",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = build_payload(args.version)
    modules = payload["modules"]

    if args.summary:
        required_count = sum(1 for setting in modules.values() if setting["required"])
        print(
            f"modules={len(modules)} required={required_count} version={payload['version']}",
            file=sys.stderr,
        )

    if args.pretty:
        print(json.dumps(payload, indent=2))
    else:
        print(json.dumps(payload, separators=(",", ":")))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
