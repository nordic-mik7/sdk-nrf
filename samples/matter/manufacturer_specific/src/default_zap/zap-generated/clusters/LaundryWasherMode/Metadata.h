// DO NOT EDIT MANUALLY - Generated file
//
// Cluster metadata information for cluster LaundryWasherMode (cluster code: 81/0x51)
// based on src/controller/data_model/controller-clusters.matter
#pragma once

#include <app/data-model-provider/MetadataTypes.h>
#include <lib/core/DataModelTypes.h>

#include <cstdint>

#include <clusters/LaundryWasherMode/Ids.h>

namespace chip
{
namespace app
{
	namespace Clusters
	{
		namespace LaundryWasherMode
		{

			inline constexpr uint32_t kRevision = 2;

			namespace Attributes
			{
				namespace SupportedModes
				{
					inline constexpr DataModel::AttributeEntry kMetadataEntry(
						SupportedModes::Id,
						BitFlags<DataModel::AttributeQualityFlags>(
							DataModel::AttributeQualityFlags::kListAttribute),
						Access::Privilege::kView, std::nullopt);
				} // namespace SupportedModes
				namespace CurrentMode
				{
					inline constexpr DataModel::AttributeEntry
						kMetadataEntry(CurrentMode::Id,
							       BitFlags<DataModel::AttributeQualityFlags>(),
							       Access::Privilege::kView, std::nullopt);
				} // namespace CurrentMode

			} // namespace Attributes

			namespace Commands
			{
				namespace ChangeToMode
				{
					inline constexpr DataModel::AcceptedCommandEntry
						kMetadataEntry(ChangeToMode::Id,
							       BitFlags<DataModel::CommandQualityFlags>(),
							       Access::Privilege::kOperate);
				} // namespace ChangeToMode

			} // namespace Commands
		} // namespace LaundryWasherMode
	} // namespace Clusters
} // namespace app
} // namespace chip
