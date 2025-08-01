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
// This file is generated from clusters-Commands.h.zapt

#pragma once

#include <app/data-model/DecodableList.h>
#include <app/data-model/Encode.h>
#include <app/data-model/List.h>
#include <app/data-model/NullObject.h>
#include <app/data-model/Nullable.h>
#include <lib/core/DataModelTypes.h>
#include <lib/core/Optional.h>
#include <lib/core/TLV.h>
#include <lib/support/BitMask.h>

#include <clusters/shared/Enums.h>
#include <clusters/shared/Structs.h>

#include <clusters/Messages/ClusterId.h>
#include <clusters/Messages/CommandIds.h>
#include <clusters/Messages/Enums.h>
#include <clusters/Messages/Structs.h>

#include <cstdint>

namespace chip
{
namespace app
{
	namespace Clusters
	{
		namespace Messages
		{
			namespace Commands
			{
				// Forward-declarations so we can reference these later.

				namespace PresentMessagesRequest
				{
					struct Type;
					struct DecodableType;
				} // namespace PresentMessagesRequest

				namespace CancelMessagesRequest
				{
					struct Type;
					struct DecodableType;
				} // namespace CancelMessagesRequest

			} // namespace Commands

			namespace Commands
			{
				namespace PresentMessagesRequest
				{
					enum class Fields : uint8_t {
						kMessageID = 0,
						kPriority = 1,
						kMessageControl = 2,
						kStartTime = 3,
						kDuration = 4,
						kMessageText = 5,
						kResponses = 6,
					};

					struct Type {
					public:
						// Use GetCommandId instead of commandId directly to avoid naming
						// conflict with CommandIdentification in ExecutionOfACommand
						static constexpr CommandId GetCommandId()
						{
							return Commands::PresentMessagesRequest::Id;
						}
						static constexpr ClusterId GetClusterId()
						{
							return Clusters::Messages::Id;
						}

						chip::ByteSpan messageID;
						MessagePriorityEnum priority = static_cast<MessagePriorityEnum>(0);
						chip::BitMask<MessageControlBitmap> messageControl =
							static_cast<chip::BitMask<MessageControlBitmap>>(0);
						DataModel::Nullable<uint32_t> startTime;
						DataModel::Nullable<uint64_t> duration;
						chip::CharSpan messageText;
						Optional<DataModel::List<const Structs::MessageResponseOptionStruct::Type>>
							responses;

						CHIP_ERROR Encode(TLV::TLVWriter &aWriter, TLV::Tag aTag) const;

						using ResponseType = DataModel::NullObjectType;

						static constexpr bool MustUseTimedInvoke() { return false; }
					};

					struct DecodableType {
					public:
						static constexpr CommandId GetCommandId()
						{
							return Commands::PresentMessagesRequest::Id;
						}
						static constexpr ClusterId GetClusterId()
						{
							return Clusters::Messages::Id;
						}
						static constexpr bool kIsFabricScoped = true;

						chip::ByteSpan messageID;
						MessagePriorityEnum priority = static_cast<MessagePriorityEnum>(0);
						chip::BitMask<MessageControlBitmap> messageControl =
							static_cast<chip::BitMask<MessageControlBitmap>>(0);
						DataModel::Nullable<uint32_t> startTime;
						DataModel::Nullable<uint64_t> duration;
						chip::CharSpan messageText;
						Optional<DataModel::DecodableList<
							Structs::MessageResponseOptionStruct::DecodableType>>
							responses;

						CHIP_ERROR Decode(TLV::TLVReader &reader,
								  FabricIndex aAccessingFabricIndex);
					};
				}; // namespace PresentMessagesRequest
				namespace CancelMessagesRequest
				{
					enum class Fields : uint8_t {
						kMessageIDs = 0,
					};

					struct Type {
					public:
						// Use GetCommandId instead of commandId directly to avoid naming
						// conflict with CommandIdentification in ExecutionOfACommand
						static constexpr CommandId GetCommandId()
						{
							return Commands::CancelMessagesRequest::Id;
						}
						static constexpr ClusterId GetClusterId()
						{
							return Clusters::Messages::Id;
						}

						DataModel::List<const chip::ByteSpan> messageIDs;

						CHIP_ERROR Encode(TLV::TLVWriter &aWriter, TLV::Tag aTag) const;

						using ResponseType = DataModel::NullObjectType;

						static constexpr bool MustUseTimedInvoke() { return false; }
					};

					struct DecodableType {
					public:
						static constexpr CommandId GetCommandId()
						{
							return Commands::CancelMessagesRequest::Id;
						}
						static constexpr ClusterId GetClusterId()
						{
							return Clusters::Messages::Id;
						}
						static constexpr bool kIsFabricScoped = true;

						DataModel::DecodableList<chip::ByteSpan> messageIDs;

						CHIP_ERROR Decode(TLV::TLVReader &reader,
								  FabricIndex aAccessingFabricIndex);
					};
				}; // namespace CancelMessagesRequest
			} // namespace Commands
		} // namespace Messages
	} // namespace Clusters
} // namespace app
} // namespace chip
