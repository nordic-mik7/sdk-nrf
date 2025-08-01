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
// This file is generated from clusters-shared-Enums.h.zapt

#pragma once

#include <stdint.h>

namespace chip
{
namespace app
{
	namespace Clusters
	{
		namespace detail
		{
			// Enums shared across multiple clusters.

			// Enum for ChangeIndicationEnum
			enum class ChangeIndicationEnum : uint8_t {
				kOk = 0x00,
				kWarning = 0x01,
				kCritical = 0x02,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 3,
			};

			// Enum for DegradationDirectionEnum
			enum class DegradationDirectionEnum : uint8_t {
				kUp = 0x00,
				kDown = 0x01,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 2,
			};

			// Enum for LevelValueEnum
			enum class LevelValueEnum : uint8_t {
				kUnknown = 0x00,
				kLow = 0x01,
				kMedium = 0x02,
				kHigh = 0x03,
				kCritical = 0x04,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 5,
			};

			// Enum for MeasurementMediumEnum
			enum class MeasurementMediumEnum : uint8_t {
				kAir = 0x00,
				kWater = 0x01,
				kSoil = 0x02,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 3,
			};

			// Enum for MeasurementTypeEnum
			enum class MeasurementTypeEnum : uint16_t {
				kUnspecified = 0x00,
				kVoltage = 0x01,
				kActiveCurrent = 0x02,
				kReactiveCurrent = 0x03,
				kApparentCurrent = 0x04,
				kActivePower = 0x05,
				kReactivePower = 0x06,
				kApparentPower = 0x07,
				kRMSVoltage = 0x08,
				kRMSCurrent = 0x09,
				kRMSPower = 0x0A,
				kFrequency = 0x0B,
				kPowerFactor = 0x0C,
				kNeutralCurrent = 0x0D,
				kElectricalEnergy = 0x0E,
				kReactiveEnergy = 0x0F,
				kApparentEnergy = 0x10,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 17,
			};

			// Enum for MeasurementUnitEnum
			enum class MeasurementUnitEnum : uint8_t {
				kPpm = 0x00,
				kPpb = 0x01,
				kPpt = 0x02,
				kMgm3 = 0x03,
				kUgm3 = 0x04,
				kNgm3 = 0x05,
				kPm3 = 0x06,
				kBqm3 = 0x07,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 8,
			};

			// Enum for ProductIdentifierTypeEnum
			enum class ProductIdentifierTypeEnum : uint8_t {
				kUpc = 0x00,
				kGtin8 = 0x01,
				kEan = 0x02,
				kGtin14 = 0x03,
				kOem = 0x04,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 5,
			};

			// Bitmaps shared across multiple clusters.

		} // namespace detail

		namespace Globals
		{
			// Global enums.

			// Enum for AreaTypeTag
			enum class AreaTypeTag : uint8_t {
				kAisle = 0x00,
				kAttic = 0x01,
				kBackDoor = 0x02,
				kBackYard = 0x03,
				kBalcony = 0x04,
				kBallroom = 0x05,
				kBathroom = 0x06,
				kBedroom = 0x07,
				kBorder = 0x08,
				kBoxroom = 0x09,
				kBreakfastRoom = 0x0A,
				kCarport = 0x0B,
				kCellar = 0x0C,
				kCloakroom = 0x0D,
				kCloset = 0x0E,
				kConservatory = 0x0F,
				kCorridor = 0x10,
				kCraftRoom = 0x11,
				kCupboard = 0x12,
				kDeck = 0x13,
				kDen = 0x14,
				kDining = 0x15,
				kDrawingRoom = 0x16,
				kDressingRoom = 0x17,
				kDriveway = 0x18,
				kElevator = 0x19,
				kEnsuite = 0x1A,
				kEntrance = 0x1B,
				kEntryway = 0x1C,
				kFamilyRoom = 0x1D,
				kFoyer = 0x1E,
				kFrontDoor = 0x1F,
				kFrontYard = 0x20,
				kGameRoom = 0x21,
				kGarage = 0x22,
				kGarageDoor = 0x23,
				kGarden = 0x24,
				kGardenDoor = 0x25,
				kGuestBathroom = 0x26,
				kGuestBedroom = 0x27,
				kGuestRoom = 0x29,
				kGym = 0x2A,
				kHallway = 0x2B,
				kHearthRoom = 0x2C,
				kKidsRoom = 0x2D,
				kKidsBedroom = 0x2E,
				kKitchen = 0x2F,
				kLaundryRoom = 0x31,
				kLawn = 0x32,
				kLibrary = 0x33,
				kLivingRoom = 0x34,
				kLounge = 0x35,
				kMediaTvRoom = 0x36,
				kMudRoom = 0x37,
				kMusicRoom = 0x38,
				kNursery = 0x39,
				kOffice = 0x3A,
				kOutdoorKitchen = 0x3B,
				kOutside = 0x3C,
				kPantry = 0x3D,
				kParkingLot = 0x3E,
				kParlor = 0x3F,
				kPatio = 0x40,
				kPlayRoom = 0x41,
				kPoolRoom = 0x42,
				kPorch = 0x43,
				kPrimaryBathroom = 0x44,
				kPrimaryBedroom = 0x45,
				kRamp = 0x46,
				kReceptionRoom = 0x47,
				kRecreationRoom = 0x48,
				kRoof = 0x4A,
				kSauna = 0x4B,
				kScullery = 0x4C,
				kSewingRoom = 0x4D,
				kShed = 0x4E,
				kSideDoor = 0x4F,
				kSideYard = 0x50,
				kSittingRoom = 0x51,
				kSnug = 0x52,
				kSpa = 0x53,
				kStaircase = 0x54,
				kSteamRoom = 0x55,
				kStorageRoom = 0x56,
				kStudio = 0x57,
				kStudy = 0x58,
				kSunRoom = 0x59,
				kSwimmingPool = 0x5A,
				kTerrace = 0x5B,
				kUtilityRoom = 0x5C,
				kWard = 0x5D,
				kWorkshop = 0x5E,
				kToilet = 0x5F,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 40,
			};

			// Enum for AtomicRequestTypeEnum
			enum class AtomicRequestTypeEnum : uint8_t {
				kBeginWrite = 0x00,
				kCommitWrite = 0x01,
				kRollbackWrite = 0x02,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 3,
			};

			// Enum for LandmarkTag
			enum class LandmarkTag : uint8_t {
				kAirConditioner = 0x00,
				kAirPurifier = 0x01,
				kBackDoor = 0x02,
				kBarStool = 0x03,
				kBathMat = 0x04,
				kBathtub = 0x05,
				kBed = 0x06,
				kBookshelf = 0x07,
				kChair = 0x08,
				kChristmasTree = 0x09,
				kCoatRack = 0x0A,
				kCoffeeTable = 0x0B,
				kCookingRange = 0x0C,
				kCouch = 0x0D,
				kCountertop = 0x0E,
				kCradle = 0x0F,
				kCrib = 0x10,
				kDesk = 0x11,
				kDiningTable = 0x12,
				kDishwasher = 0x13,
				kDoor = 0x14,
				kDresser = 0x15,
				kLaundryDryer = 0x16,
				kFan = 0x17,
				kFireplace = 0x18,
				kFreezer = 0x19,
				kFrontDoor = 0x1A,
				kHighChair = 0x1B,
				kKitchenIsland = 0x1C,
				kLamp = 0x1D,
				kLitterBox = 0x1E,
				kMirror = 0x1F,
				kNightstand = 0x20,
				kOven = 0x21,
				kPetBed = 0x22,
				kPetBowl = 0x23,
				kPetCrate = 0x24,
				kRefrigerator = 0x25,
				kScratchingPost = 0x26,
				kShoeRack = 0x27,
				kShower = 0x28,
				kSideDoor = 0x29,
				kSink = 0x2A,
				kSofa = 0x2B,
				kStove = 0x2C,
				kTable = 0x2D,
				kToilet = 0x2E,
				kTrashCan = 0x2F,
				kLaundryWasher = 0x30,
				kWindow = 0x31,
				kWineCooler = 0x32,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 51,
			};

			// Enum for LocationTag
			enum class LocationTag : uint8_t {
				kIndoor = 0x00,
				kOutdoor = 0x01,
				kInside = 0x02,
				kOutside = 0x03,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 4,
			};

			// Enum for MeasurementTypeEnum
			enum class MeasurementTypeEnum : uint16_t {
				kUnspecified = 0x00,
				kVoltage = 0x01,
				kActiveCurrent = 0x02,
				kReactiveCurrent = 0x03,
				kApparentCurrent = 0x04,
				kActivePower = 0x05,
				kReactivePower = 0x06,
				kApparentPower = 0x07,
				kRMSVoltage = 0x08,
				kRMSCurrent = 0x09,
				kRMSPower = 0x0A,
				kFrequency = 0x0B,
				kPowerFactor = 0x0C,
				kNeutralCurrent = 0x0D,
				kElectricalEnergy = 0x0E,
				kReactiveEnergy = 0x0F,
				kApparentEnergy = 0x10,
				kSoilMoisture = 0x11,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 18,
			};

			// Enum for PositionTag
			enum class PositionTag : uint8_t {
				kLeft = 0x00,
				kRight = 0x01,
				kTop = 0x02,
				kBottom = 0x03,
				kMiddle = 0x04,
				kRow = 0x05,
				kColumn = 0x06,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 7,
			};

			// Enum for PowerThresholdSourceEnum
			enum class PowerThresholdSourceEnum : uint8_t {
				kContract = 0x00,
				kRegulator = 0x01,
				kEquipment = 0x02,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 3,
			};

			// Enum for RelativePositionTag
			enum class RelativePositionTag : uint8_t {
				kUnder = 0x00,
				kNextTo = 0x01,
				kAround = 0x02,
				kOn = 0x03,
				kAbove = 0x04,
				kFrontOf = 0x05,
				kBehind = 0x06,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 7,
			};

			// Enum for StreamUsageEnum
			enum class StreamUsageEnum : uint8_t {
				kInternal = 0x00,
				kRecording = 0x01,
				kAnalysis = 0x02,
				kLiveView = 0x03,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 4,
			};

			// Enum for TariffPriceTypeEnum
			enum class TariffPriceTypeEnum : uint8_t {
				kStandard = 0x00,
				kCritical = 0x01,
				kVirtual = 0x02,
				kIncentive = 0x03,
				kIncentiveSignal = 0x04,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 5,
			};

			// Enum for TariffUnitEnum
			enum class TariffUnitEnum : uint8_t {
				kKWh = 0x00,
				kKVAh = 0x01,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 2,
			};

			// Enum for TestGlobalEnum
			enum class TestGlobalEnum : uint8_t {
				kSomeValue = 0x00,
				kSomeOtherValue = 0x01,
				kFinalValue = 0x02,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 3,
			};

			// Enum for ThreeLevelAutoEnum
			enum class ThreeLevelAutoEnum : uint8_t {
				kAuto = 0x00,
				kLow = 0x01,
				kMedium = 0x02,
				kHigh = 0x03,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 4,
			};

			// Enum for WebRTCEndReasonEnum
			enum class WebRTCEndReasonEnum : uint8_t {
				kIceFailed = 0x00,
				kIceTimeout = 0x01,
				kUserHangup = 0x02,
				kUserBusy = 0x03,
				kReplaced = 0x04,
				kNoUserMedia = 0x05,
				kInviteTimeout = 0x06,
				kAnsweredElsewhere = 0x07,
				kOutOfResources = 0x08,
				kMediaTimeout = 0x09,
				kLowPower = 0x0A,
				kUnknownReason = 0x0B,
				// All received enum values that are not listed above will be mapped
				// to kUnknownEnumValue. This is a helper enum value that should only
				// be used by code to process how it handles receiving and unknown
				// enum value. This specific should never be transmitted.
				kUnknownEnumValue = 12,
			};

			// Global bitmaps.

			// Bitmap for TestGlobalBitmap
			enum class TestGlobalBitmap : uint32_t {
				kFirstBit = 0x1,
				kSecondBit = 0x2,
			};

		} // namespace Globals
	} // namespace Clusters
} // namespace app
} // namespace chip
