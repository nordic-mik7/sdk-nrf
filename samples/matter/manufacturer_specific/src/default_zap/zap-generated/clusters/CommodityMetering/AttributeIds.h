// DO NOT EDIT MANUALLY - Generated file
//
// Identifier constant values for cluster CommodityMetering (cluster code: 2823/0xB07)
// based on src/controller/data_model/controller-clusters.matter
#pragma once

#include <clusters/shared/GlobalIds.h>
#include <lib/core/DataModelTypes.h>

namespace chip
{
namespace app
{
	namespace Clusters
	{
		namespace CommodityMetering
		{
			namespace Attributes
			{
				namespace MeteredQuantity
				{
					inline constexpr AttributeId Id = 0x00000000;
				} // namespace MeteredQuantity

				namespace MeteredQuantityTimestamp
				{
					inline constexpr AttributeId Id = 0x00000001;
				} // namespace MeteredQuantityTimestamp

				namespace MeasurementType
				{
					inline constexpr AttributeId Id = 0x00000002;
				} // namespace MeasurementType

				namespace GeneratedCommandList
				{
					inline constexpr AttributeId Id = Globals::Attributes::GeneratedCommandList::Id;
				} // namespace GeneratedCommandList

				namespace AcceptedCommandList
				{
					inline constexpr AttributeId Id = Globals::Attributes::AcceptedCommandList::Id;
				} // namespace AcceptedCommandList

				namespace AttributeList
				{
					inline constexpr AttributeId Id = Globals::Attributes::AttributeList::Id;
				} // namespace AttributeList

				namespace FeatureMap
				{
					inline constexpr AttributeId Id = Globals::Attributes::FeatureMap::Id;
				} // namespace FeatureMap

				namespace ClusterRevision
				{
					inline constexpr AttributeId Id = Globals::Attributes::ClusterRevision::Id;
				} // namespace ClusterRevision

			} // namespace Attributes
		} // namespace CommodityMetering
	} // namespace Clusters
} // namespace app
} // namespace chip
