/*
 *
 *    Copyright (c) 2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

// THIS FILE IS GENERATED BY ZAP
// This file is generated from clusters-Enums-Check.h.zapt

#pragma once

#include <clusters/OtaSoftwareUpdateProvider/Enums.h>

namespace chip
{
namespace app
{
	namespace Clusters
	{
		static auto __attribute__((unused))
		EnsureKnownEnumValue(OtaSoftwareUpdateProvider::ApplyUpdateActionEnum val)
		{
			using EnumType = OtaSoftwareUpdateProvider::ApplyUpdateActionEnum;
			switch (val) {
			case EnumType::kProceed:
			case EnumType::kAwaitNextAction:
			case EnumType::kDiscontinue:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused))
		EnsureKnownEnumValue(OtaSoftwareUpdateProvider::DownloadProtocolEnum val)
		{
			using EnumType = OtaSoftwareUpdateProvider::DownloadProtocolEnum;
			switch (val) {
			case EnumType::kBDXSynchronous:
			case EnumType::kBDXAsynchronous:
			case EnumType::kHttps:
			case EnumType::kVendorSpecific:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(OtaSoftwareUpdateProvider::StatusEnum val)
		{
			using EnumType = OtaSoftwareUpdateProvider::StatusEnum;
			switch (val) {
			case EnumType::kUpdateAvailable:
			case EnumType::kBusy:
			case EnumType::kNotAvailable:
			case EnumType::kDownloadProtocolNotSupported:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
	} // namespace Clusters
} // namespace app
} // namespace chip
