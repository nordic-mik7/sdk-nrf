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

#include <clusters/DoorLock/Enums.h>

namespace chip
{
namespace app
{
	namespace Clusters
	{
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::AlarmCodeEnum val)
		{
			using EnumType = DoorLock::AlarmCodeEnum;
			switch (val) {
			case EnumType::kLockJammed:
			case EnumType::kLockFactoryReset:
			case EnumType::kLockRadioPowerCycled:
			case EnumType::kWrongCodeEntryLimit:
			case EnumType::kFrontEsceutcheonRemoved:
			case EnumType::kDoorForcedOpen:
			case EnumType::kDoorAjar:
			case EnumType::kForcedUser:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::CredentialRuleEnum val)
		{
			using EnumType = DoorLock::CredentialRuleEnum;
			switch (val) {
			case EnumType::kSingle:
			case EnumType::kDual:
			case EnumType::kTri:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::CredentialTypeEnum val)
		{
			using EnumType = DoorLock::CredentialTypeEnum;
			switch (val) {
			case EnumType::kProgrammingPIN:
			case EnumType::kPin:
			case EnumType::kRfid:
			case EnumType::kFingerprint:
			case EnumType::kFingerVein:
			case EnumType::kFace:
			case EnumType::kAliroCredentialIssuerKey:
			case EnumType::kAliroEvictableEndpointKey:
			case EnumType::kAliroNonEvictableEndpointKey:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::DataOperationTypeEnum val)
		{
			using EnumType = DoorLock::DataOperationTypeEnum;
			switch (val) {
			case EnumType::kAdd:
			case EnumType::kClear:
			case EnumType::kModify:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::DlLockState val)
		{
			using EnumType = DoorLock::DlLockState;
			switch (val) {
			case EnumType::kNotFullyLocked:
			case EnumType::kLocked:
			case EnumType::kUnlocked:
			case EnumType::kUnlatched:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::DlLockType val)
		{
			using EnumType = DoorLock::DlLockType;
			switch (val) {
			case EnumType::kDeadBolt:
			case EnumType::kMagnetic:
			case EnumType::kOther:
			case EnumType::kMortise:
			case EnumType::kRim:
			case EnumType::kLatchBolt:
			case EnumType::kCylindricalLock:
			case EnumType::kTubularLock:
			case EnumType::kInterconnectedLock:
			case EnumType::kDeadLatch:
			case EnumType::kDoorFurniture:
			case EnumType::kEurocylinder:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::DlStatus val)
		{
			using EnumType = DoorLock::DlStatus;
			switch (val) {
			case EnumType::kSuccess:
			case EnumType::kFailure:
			case EnumType::kDuplicate:
			case EnumType::kOccupied:
			case EnumType::kInvalidField:
			case EnumType::kResourceExhausted:
			case EnumType::kNotFound:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::DoorLockOperationEventCode val)
		{
			using EnumType = DoorLock::DoorLockOperationEventCode;
			switch (val) {
			case EnumType::kUnknownOrMfgSpecific:
			case EnumType::kLock:
			case EnumType::kUnlock:
			case EnumType::kLockInvalidPinOrId:
			case EnumType::kLockInvalidSchedule:
			case EnumType::kUnlockInvalidPinOrId:
			case EnumType::kUnlockInvalidSchedule:
			case EnumType::kOneTouchLock:
			case EnumType::kKeyLock:
			case EnumType::kKeyUnlock:
			case EnumType::kAutoLock:
			case EnumType::kScheduleLock:
			case EnumType::kScheduleUnlock:
			case EnumType::kManualLock:
			case EnumType::kManualUnlock:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::DoorLockProgrammingEventCode val)
		{
			using EnumType = DoorLock::DoorLockProgrammingEventCode;
			switch (val) {
			case EnumType::kUnknownOrMfgSpecific:
			case EnumType::kMasterCodeChanged:
			case EnumType::kPinAdded:
			case EnumType::kPinDeleted:
			case EnumType::kPinChanged:
			case EnumType::kIdAdded:
			case EnumType::kIdDeleted:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::DoorLockSetPinOrIdStatus val)
		{
			using EnumType = DoorLock::DoorLockSetPinOrIdStatus;
			switch (val) {
			case EnumType::kSuccess:
			case EnumType::kGeneralFailure:
			case EnumType::kMemoryFull:
			case EnumType::kDuplicateCodeError:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::DoorLockUserStatus val)
		{
			using EnumType = DoorLock::DoorLockUserStatus;
			switch (val) {
			case EnumType::kAvailable:
			case EnumType::kOccupiedEnabled:
			case EnumType::kOccupiedDisabled:
			case EnumType::kNotSupported:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::DoorLockUserType val)
		{
			using EnumType = DoorLock::DoorLockUserType;
			switch (val) {
			case EnumType::kUnrestricted:
			case EnumType::kYearDayScheduleUser:
			case EnumType::kWeekDayScheduleUser:
			case EnumType::kMasterUser:
			case EnumType::kNonAccessUser:
			case EnumType::kNotSupported:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::DoorStateEnum val)
		{
			using EnumType = DoorLock::DoorStateEnum;
			switch (val) {
			case EnumType::kDoorOpen:
			case EnumType::kDoorClosed:
			case EnumType::kDoorJammed:
			case EnumType::kDoorForcedOpen:
			case EnumType::kDoorUnspecifiedError:
			case EnumType::kDoorAjar:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::LockDataTypeEnum val)
		{
			using EnumType = DoorLock::LockDataTypeEnum;
			switch (val) {
			case EnumType::kUnspecified:
			case EnumType::kProgrammingCode:
			case EnumType::kUserIndex:
			case EnumType::kWeekDaySchedule:
			case EnumType::kYearDaySchedule:
			case EnumType::kHolidaySchedule:
			case EnumType::kPin:
			case EnumType::kRfid:
			case EnumType::kFingerprint:
			case EnumType::kFingerVein:
			case EnumType::kFace:
			case EnumType::kAliroCredentialIssuerKey:
			case EnumType::kAliroEvictableEndpointKey:
			case EnumType::kAliroNonEvictableEndpointKey:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::LockOperationTypeEnum val)
		{
			using EnumType = DoorLock::LockOperationTypeEnum;
			switch (val) {
			case EnumType::kLock:
			case EnumType::kUnlock:
			case EnumType::kNonAccessUserEvent:
			case EnumType::kForcedUserEvent:
			case EnumType::kUnlatch:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::OperatingModeEnum val)
		{
			using EnumType = DoorLock::OperatingModeEnum;
			switch (val) {
			case EnumType::kNormal:
			case EnumType::kVacation:
			case EnumType::kPrivacy:
			case EnumType::kNoRemoteLockUnlock:
			case EnumType::kPassage:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::OperationErrorEnum val)
		{
			using EnumType = DoorLock::OperationErrorEnum;
			switch (val) {
			case EnumType::kUnspecified:
			case EnumType::kInvalidCredential:
			case EnumType::kDisabledUserDenied:
			case EnumType::kRestricted:
			case EnumType::kInsufficientBattery:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::OperationSourceEnum val)
		{
			using EnumType = DoorLock::OperationSourceEnum;
			switch (val) {
			case EnumType::kUnspecified:
			case EnumType::kManual:
			case EnumType::kProprietaryRemote:
			case EnumType::kKeypad:
			case EnumType::kAuto:
			case EnumType::kButton:
			case EnumType::kSchedule:
			case EnumType::kRemote:
			case EnumType::kRfid:
			case EnumType::kBiometric:
			case EnumType::kAliro:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::UserStatusEnum val)
		{
			using EnumType = DoorLock::UserStatusEnum;
			switch (val) {
			case EnumType::kAvailable:
			case EnumType::kOccupiedEnabled:
			case EnumType::kOccupiedDisabled:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
		static auto __attribute__((unused)) EnsureKnownEnumValue(DoorLock::UserTypeEnum val)
		{
			using EnumType = DoorLock::UserTypeEnum;
			switch (val) {
			case EnumType::kUnrestrictedUser:
			case EnumType::kYearDayScheduleUser:
			case EnumType::kWeekDayScheduleUser:
			case EnumType::kProgrammingUser:
			case EnumType::kNonAccessUser:
			case EnumType::kForcedUser:
			case EnumType::kDisposableUser:
			case EnumType::kExpiringUser:
			case EnumType::kScheduleRestrictedUser:
			case EnumType::kRemoteOnlyUser:
				return val;
			default:
				return EnumType::kUnknownEnumValue;
			}
		}
	} // namespace Clusters
} // namespace app
} // namespace chip
