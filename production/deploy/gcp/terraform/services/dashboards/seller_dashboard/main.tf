# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

resource "google_monitoring_dashboard" "environment_dashboard" {
  dashboard_json = <<EOF
{
  "displayName": "${var.environment} Seller Metrics",
  "mosaicLayout": {
    "columns": 48,
    "tiles": [
      {
        "height": 19,
        "widget": {
          "title": "request.count [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/request.count\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24
      },
      {
        "height": 19,
        "widget": {
          "title": "system.cpu.percent [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"label\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/system.cpu.percent\" resource.type=\"generic_task\" metric.label.\"label\"!=\"total cpu cores\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 38
      },
      {
        "height": 19,
        "widget": {
          "title": "request.duration_ms [95TH PERCENTILE]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_95",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_DELTA"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/request.duration_ms\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24
      },
      {
        "height": 19,
        "widget": {
          "title": "system.memory.usage_kb for main process [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/system.memory.usage_kb\" resource.type=\"generic_task\" metric.label.\"label\"=\"main process\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 57
      },
      {
        "height": 19,
        "widget": {
          "title": "system.memory.usage_kb for MemAvailable: [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"label\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/system.memory.usage_kb\" resource.type=\"generic_task\" metric.label.\"label\"=\"MemAvailable:\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 76
      },
      {
        "height": 19,
        "widget": {
          "title": "request.size_bytes [95TH PERCENTILE]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_95",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_DELTA"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/request.size_bytes\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 19
      },
      {
        "height": 19,
        "widget": {
          "title": "response.size_bytes [95TH PERCENTILE]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_95",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_DELTA"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/response.size_bytes\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 38
      },
      {
        "height": 19,
        "widget": {
          "title": "js_execution.duration_ms [95TH PERCENTILE]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_95",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_DELTA"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/js_execution.duration_ms\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 285
      },
      {
        "height": 19,
        "widget": {
          "title": "initiated_request.bfe.errors_count_by_status [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/initiated_request.bfe.errors_count_by_status\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"error_status_code\"",
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 171
      },
      {
        "height": 19,
        "widget": {
          "title": "js_execution.error.count [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/js_execution.error.count\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos":24,
        "yPos": 285
      },
      {
        "height": 16,
        "widget": {
          "title": "business_logic.auction.bids.count [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/business_logic.auction.bids.count\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 304
      },
      {
        "height": 16,
        "widget": {
          "title": "business_logic.auction.bid_rejected.count [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/business_logic.auction.bid_rejected.count\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"seller_rejection_reason\"",
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 304
      },
      {
        "height": 19,
        "widget": {
          "title": "initiated_request.kv.duration_ms [95TH PERCENTILE]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_95",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_DELTA"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/initiated_request.kv.duration_ms\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 190
      },
      {
        "height": 19,
        "widget": {
          "title": "initiated_request.count_by_server [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/initiated_request.count_by_server\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"server_name\"",
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 95
      },
      {
        "height": 19,
        "widget": {
          "title": "business_logic.auction.bid_rejected.percent [95TH PERCENTILE]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_95",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_DELTA"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/business_logic.auction.bid_rejected.percent\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 323
      },
      {
        "height": 19,
        "widget": {
          "title": "initiated_request.auction.size_bytes [95TH PERCENTILE]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_95",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_DELTA"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/initiated_request.auction.size_bytes\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 171
      },
      {
        "height": 19,
        "widget": {
          "title": "initiated_request.auction.duration_ms [95TH PERCENTILE]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_95",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_DELTA"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/initiated_request.auction.duration_ms\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 152
      },
      {
        "height": 19,
        "widget": {
          "title": "initiated_request.kv.size_bytes [95TH PERCENTILE]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_95",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_DELTA"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/initiated_request.kv.size_bytes\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"  metric.label.\"service_name\"=\"sfe\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 209
      },
      {
        "height": 19,
        "widget": {
          "title": "sfe.initiated_response.kv.size_bytes [95TH PERCENTILE]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_95",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_DELTA"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/sfe.initiated_response.kv.size_bytes\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"  metric.label.\"service_name\"=\"sfe\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 228
      },
      {
        "height": 19,
        "widget": {
          "title": "sfe.error_code [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/sfe.error_code\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"error_code\"",
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 133
      },
      {
        "height": 19,
        "widget": {
          "title": "auction.error_code [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/auction.error_code\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"error_code\"",
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 133
      },
  {
        "height": 19,
        "widget": {
          "title": "initiated_request.kv.errors_count_by_status [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/initiated_request.kv.errors_count_by_status\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"error_status_code\"",
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 190
      },
      {
        "height": 19,
        "widget": {
          "title": "initiated_request.auction.errors_count_by_status [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/initiated_request.auction.errors_count_by_status\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"error_status_code\"",
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 152
      },
      {
        "height": 19,
        "widget": {
          "title": "request.failed_count_by_status [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/request.failed_count_by_status\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"error_status_code\"",
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 19
      },
      {
        "height": 19,
        "widget": {
          "title": "initiated_response.auction.size_bytes [95TH PERCENTILE]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_95",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_DELTA"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/initiated_response.auction.size_bytes\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 209
      },
      {
        "height": 19,
        "widget": {
          "title": "system.thread.count [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"label\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/system.thread.count\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 76
      },
      {
        "height": 19,
        "widget": {
          "title": "sfe.initiated_request.errors_count_by_buyer [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/sfe.initiated_request.errors_count_by_buyer\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"buyer\"",
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 247
      },
      {
        "height": 19,
        "widget": {
          "title": "sfe.initiated_request.count_by_buyer [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/sfe.initiated_request.count_by_buyer\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"buyer\"",
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 228
      },
      {
        "height": 19,
        "widget": {
          "title": "sfe.initiated_request.duration_by_buyer [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/sfe.initiated_request.duration_by_buyer\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"buyer\"",
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 247
      },
      {
        "height": 19,
        "widget": {
            "title": "sfe.initiated_request.size_by_buyer [MEAN]",
            "xyChart": {
              "chartOptions": {},
              "dataSets": [
                {
                  "minAlignmentPeriod": "60s",
                  "plotType": "LINE",
                  "targetAxis": "Y1",
                  "timeSeriesQuery": {
                    "timeSeriesFilter": {
                      "aggregation": {
                        "alignmentPeriod": "60s",
                        "perSeriesAligner": "ALIGN_RATE"
                      },
                      "filter": "metric.type=\"workload.googleapis.com/sfe.initiated_request.size_by_buyer\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                      "secondaryAggregation": {
                        "alignmentPeriod": "60s",
                        "crossSeriesReducer": "REDUCE_MEAN",
                        "groupByFields": [
                          "metric.label.\"buyer\"",
                          "metric.label.\"service_name\"",
                          "metric.label.\"deployment_environment\"",
                          "metric.label.\"operator\"",
                          "metric.label.\"Noise\"",
                          "resource.label.\"task_id\"",
                          "metric.label.\"service_version\""
                        ],
                        "perSeriesAligner": "ALIGN_MEAN"
                      }
                    }
                  }
                }
              ],
              "yAxis": {
                "scale": "LINEAR"
              }
            }
          },
          "width": 24,
          "yPos": 266
      },
      {
        "height": 19,
        "widget": {
          "title": "sfe.initiated_response.size_by_buyer [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/sfe.initiated_response.size_by_buyer\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"buyer\"",
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 266
      },
      {
        "height": 19,
        "widget": {
          "title": "system.key_fetch.failure_count [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"label\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/system.key_fetch.failure_count\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 95
      },
      {
        "height": 19,
        "widget": {
          "title": "system.key_fetch.num_keys_parsed_on_recent_fetch [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"label\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/system.key_fetch.num_keys_parsed_on_recent_fetch\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 114
      },
      {
        "height": 19,
        "widget": {
          "title": "system.key_fetch.num_keys_cached_after_recent_fetch [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"label\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/system.key_fetch.num_keys_cached_after_recent_fetch\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 114
      },
      {
        "height": 19,
        "widget": {
          "title": "system.cpu.total_cores [MEAN]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/system.cpu.percent\" resource.type=\"generic_task\" metric.label.\"label\"=\"total cpu cores\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "yPos": 57
      },
      {
        "height": 19,
        "widget": {
          "title": "business_logic.sfe.request_with_winner.count",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/business_logic.sfe.request_with_winner.count\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\"",
                    "secondaryAggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_MEAN"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 320
      },
      {
        "height": 19,
        "widget": {
          "title": "business_logic.sfe.request_with_winner.duration_ms [95TH PERCENTILE]",
          "xyChart": {
            "chartOptions": {},
            "dataSets": [
              {
                "minAlignmentPeriod": "60s",
                "plotType": "LINE",
                "targetAxis": "Y1",
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_95",
                      "groupByFields": [
                        "metric.label.\"service_name\"",
                        "metric.label.\"deployment_environment\"",
                        "metric.label.\"operator\"",
                        "metric.label.\"Noise\"",
                        "resource.label.\"task_id\"",
                        "metric.label.\"service_version\""
                      ],
                      "perSeriesAligner": "ALIGN_DELTA"
                    },
                    "filter": "metric.type=\"workload.googleapis.com/business_logic.sfe.request_with_winner.duration_ms\" resource.type=\"generic_task\" metric.label.\"deployment_environment\"=\"${var.environment}\""
                  }
                }
              }
            ],
            "yAxis": {
              "scale": "LINEAR"
            }
          }
        },
        "width": 24,
        "xPos": 24,
        "yPos": 339
      }
    ]
  }
}
EOF
}
