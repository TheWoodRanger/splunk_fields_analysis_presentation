# Splunk Fieldsummary & Fields Derivation Example References

Reference [Splunk Docs on Fieldsummary Command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Fieldsummary)

## A Word of Warning!

***I recommend you use | loadjob when using these, as it's best to run `| map` under controlled conditions! Limit number on `maxvals` setting to avoid high compute! Lower `maxvals` or specify more strict initial filters for your map searches if you experience long runtimes/too much compute.***




----------------------------------------------------------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------------------------------------------------------

## Other Splunk .conf Presentations I recommend

**"I stand on the shoulders of giants."**


| Presentations                                                                                                                                                                             |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Security Ninjutsu Part 4](http://conf.splunk.com/files/2017/slides/security-ninjutsu-part-four-attackers-be-gone-in-45-minutes-of-epic-spl.pdf)                                          |
| [Ninjutsu Part 6](https://www.davidveuve.com/splunk.html#ninjutsupartsix)                                                                                                                 |
| [Tricks for better SPL](https://conf.splunk.com/files/2019/slides/FN1300.pdf)                                                                                                             |
| [Lesser Known Search Commands](https://conf.splunk.com/files/2019/slides/FN1061.pdf)                                                                                                      |
| [SPL Tips - How to fall in love with Splunk](https://conf.splunk.com/files/2019/slides/FN1300.pdf)                                                                                        |
| [Master Joining Datasets without Using Join](https://conf.splunk.com/files/2020/slides/TRU1761C.pdf)                                                                                      |
| [Turning Security Use Cases into SPL](https://static.rainfocus.com/splunk/splunkconf18/sess/1523489574149001lr6z/finalPDF/SEC1583_TurningSecurityUseCases_Final_1538510573435001VmSg.pdf) |



----------------------------------------------------------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------------------------------------------------------

## `fieldsummary_simple`

- A simple version of a fieldsummary
- Provides a very direct “show me the fields” view that can save a lot of time and be run on the fly.
- Macro-able

**NOTE: This will return the first value found in any event, not just the first event. Returns the first value of any multivalue fields.**

### fieldsummary_simple Query

```spl
| stats first(*) AS * 
| transpose 0 column_name="field" 
| rename "row 1" as first_value
```

### fieldsummary_simple Macro Conf

```conf
[fieldsummary_simple]
definition = stats first(*) AS * \
| transpose 0 column_name="field" \
| rename "row 1" AS first_value
iseval = 0
```

----------------------------------------------------------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------------------------------------------------------

### Fields Derivation Query

- Gathers field object information and combines it together into a single view
  - Calculated Fields / props.conf / transforms.conf / Aliases / Lookups
- Outputs final field set of common elements like title, field name, stanza, app, etc, then stores all conf-specific configurations/properties in the `conf_specific_properties_mv` field


```spl
| makeresults | where 1==2 
| append 
    [| rest /services/data/props/calcfields 
    | dedup id 
    | rename field.name AS field_name, eai:acl.* AS acl_* 
    | table dataSource, title, field_name, stanza, type, attribute, acl_app, acl_owner, acl_sharing, value 
    | eval dataSource = "props-calcfields"] 
| append 
    [| rest /services/data/props/extractions 
    | dedup id 
    | rename eai:acl.* AS acl_* 
    | rex field=attribute "^[^-]+-(?<field_name>.+)" 
    | table dataSource, title, field_name, stanza, type, attribute, acl_app, acl_owner, acl_sharing, value 
    | eval dataSource = "props-extractions"] 
| append 
    [| rest /services/data/props/fieldaliases 
    | dedup id 
    | foreach alias.* 
        [| eval conf_specific_properties_mv = case(
            isnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>'), "<<FIELD>>::::" . '<<FIELD>>', 
            isnotnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>'), mvappend(conf_specific_properties_mv, "<<FIELD>>::::" . '<<FIELD>>'), 
            isnotnull(conf_specific_properties_mv) AND isnull('<<FIELD>>'), conf_specific_properties_mv
            )] 
    | rename eai:acl.* AS acl_* 
    | rex field=attribute "^[^-]+-(?<field_name>.+)" 
    | table dataSource, title, field_name, stanza, type, attribute, acl_app, acl_owner, acl_sharing, value, conf_specific_properties_mv 
    | eval dataSource = "props-fieldaliases"] 
| append 
    [| rest /services/data/transforms/extractions 
    | dedup id 
    | rename eai:acl.* AS acl_*, REGEX AS value 
    | foreach * 
        [| eval <<FIELD>> = if( match('<<FIELD>>', "."), '<<FIELD>>', null() )] 
    | foreach FORMAT, CAN_OPTIMIZE, CLEAN_KEYS, DEFAULT_VALUE, SOURCE_KEY, DEST_KEY, WRITE_META, DELIMS, FIELDS, KEEP_EMPTY_VALS, LOOKAHEAD, MATCH_LIMIT, MV_ADD, REPEAT_MATCH 
        [| eval conf_specific_properties_mv = case(isnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>'), "<<FIELD>>::::" . '<<FIELD>>', isnotnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>'), mvappend(conf_specific_properties_mv, "<<FIELD>>::::" . '<<FIELD>>'), isnotnull(conf_specific_properties_mv) AND isnull('<<FIELD>>'), conf_specific_properties_mv)] 
    | eval stanza = title 
    | table dataSource, title, stanza, acl_app, acl_owner, acl_sharing, value, conf_specific_properties_mv 
    | eval dataSource = "transforms-extractions"] 
| append 
    [| rest /services/data/props/lookups 
    | dedup id 
    | rename eai:acl.* AS acl_*, lookup.field.output.* AS field_output_*, lookup.field.input.* AS field_input_*, transform AS transforms_stanza 
    | foreach * 
        [| eval <<FIELD>> = if( match('<<FIELD>>', "."), '<<FIELD>>', null() )] 
    | foreach field_output_*, field_input_* 
        [| eval field_name = case(
            isnull(field_name) AND isnotnull('<<FIELD>>'), "<<FIELD>>::::" . '<<FIELD>>', 
            isnotnull(field_name) AND isnotnull('<<FIELD>>'), mvappend(field_name, "<<FIELD>>::::" . '<<FIELD>>'), 
            isnotnull(field_name) AND isnull('<<FIELD>>'), field_name
            )] 
    | foreach field_name, overwrite, transforms_stanza 
        [| eval conf_specific_properties_mv = case(isnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>') AND match("<<FIELD>>", "field_name"), '<<FIELD>>', isnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>'), "<<FIELD>>::::" . '<<FIELD>>', isnotnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>') AND match("<<FIELD>>", "field_name"), mvap(conf_specific_properties_mv, '<<FIELD>>'), isnotnull(conf_specific_properties_mv) AND isnotnull('<<FIELD>>'), mvappend(conf_specific_properties_mv, "<<FIELD>>::::" . '<<FIELD>>'), isnotnull(conf_specific_properties_mv) AND isnull('<<FIELD>>'), conf_specific_properties_mv)] 
    | eval stanza = title 
    | table dataSource, field_name, title, stanza, type, attribute, acl_app, acl_owner, acl_sharing, value, conf_specific_properties_mv 
    | eval dataSource = "props-lookups (automatic lookups)"] 
| table dataSource, field_name, stanza, type, attribute, acl_app, acl_owner, acl_sharing, title, value, conf_specific_properties_mv
```

----------------------------------------------------------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------------------------------------------------------

## Notes on Using `| fieldsummary` Examples Below

### Customization Options

| Line                                         | Customization                                                                                                  |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| `where (tonumber(rtrim(diffPerc,"%")) > 10)` | Modify minimum % field coverage for a field to be included in results                                          |
| `fieldsummary maxvals=[int]`                 | Determines how many unique values are returned in the values field. Caution: more values means higher compute. |
| `map maxsearches=[int]`                      | Make sure the maxsearches for your map command is set high enough to account for the variance in your group-by |



----------------------------------------------------------------------------------------------------------------------------------------------------------------

## Fieldsummary Examples

**Note: Remove all `| eval comment` lines if desired.**

### Fieldsummary - No Group-By



```spl
index=_internal sourcetype=splunkd 
| eval comment = if(1==1, null(), "
START initial fieldsummary command execution.
    Note: Remove any fields desired. Modify 'maxvals' setting to desired number of output values. 'DistinctValues' calculation is up to 5x the maxvals specified.
    Fieldsummary command accepts list of fields as filter. Leave empty for '*' all fields.
") 
| fields - date_*, host, linecount, punct, splunk_server*, timestartpos, timeendpos, timestamp 
| fieldsummary maxvals=5 
| eval comment = if(1==1, null(), "
END initial fieldsummary command execution.


START fieldsummary transformations and base calculations/filtering.
") 
| eval distinctValues=case((is_exact == 1),(distinct_count . " (Exact)"),(is_exact == 0),(distinct_count . " (Estimate)")) 
| eventstats max(count) as eventCount 
| eval diffPerc=(round(((count / eventCount) * 100),1) . "%") 
| eval comment = if(1==1, null(), "
    Note: Modify | where command below based on desired minimum % of events containing a field with values for that field to be displayed.")
| where (tonumber(rtrim(diffPerc,"%")) > 10) 
| fields - distinct_count, eventCount, is_exact, mean, max, min, stdev
| eval comment = if(1==1, null(), "
END fieldsummary transformations and base calculations/filtering.


START reformatting of 'values' JSON data into readable Multivalue field.
") 
| spath input=values path="{}.value" output="value_strings" 
| eval comment = if(1==1, null(), "
    Note: Wrap the value_strings field with doublequotes through multivalue functions without expanding by using ':::' as a delimiter.") 
| eval value_strings = split("\"" . mvjoin(value_strings, "\":::\"") . "\"", ":::") 
| spath input=values path="{}.count" output="value_counts" 
| eval comment = if(1==1, null(), "
    Note: Concat the two into a single MV field, formatted as 'value_strings': value_counts") 
| eval values = mvzip(value_strings, value_counts, ": ") 
| fields - value_counts, value_strings 
| eval comment = if(1==1, null(), "
END reformatting of 'values' JSON data into readable Multivalue field.


START column alignment formatting for values field. 
    Note: column alignment, if calculated on the aggregate dataset without GROUPBY, can result in wrapped lines if the dataset contains any fields with long values.") 
| mvexpand values 
| rex field=values "^(?<fieldValueString>\".+\"):\s(?<fieldValueCount>\d+)" 
| eventstats max(eval(len(fieldValueString))) AS max_fieldValue_len BY field 
| eval whitespaceInsertAmount=((max_fieldValue_len + 4) - len(fieldValueString)) 
| eval values = fieldValueString . substr("                                                                                                                                                           ",1,whitespaceInsertAmount) . ":" . fieldValueCount 
| fields - whitespaceInsertAmount, max_fieldValue_len, fieldValueString, fieldValueCount 
| stats list(values) AS values, values(values) AS values_ThisMustBeSeparateToRetainOrdering, values(*) AS * BY field 
| fields - values_ThisMustBeSeparateToRetainOrdering
| eval comment = if(1==1, null(), "
END column alignment formatting for values field.


START row deduplication/aggregation of duplicate information across multiple fields into a single row through using a md5 hash. If all the columns EXCEPT field name are equivalent, aggregate.
") 
| eval valuesHash = md5(mvjoin(values, ":::")) 
| eval checkSum = md5( count . ":::" . diffPerc . ":::" . numeric_count . ":::" . distinctValues . ":::" . valuesHash) 
| eventstats values(field) AS field BY checkSum 
| sort 0 - checkSum 
| streamstats count AS duplicateCount BY checkSum 
| where duplicateCount < 2 
| eval comment = if(1==1, null(), "
END row deduplication/aggregation of duplicate information across multiple fields into a single row through using a md5 hash.
") 
| sort 0 - count 
| table field, count, diffPerc, numeric_count, distinctValues, values
| rename count as "Count of Events w/ Field", diffPerc as "Perc of Total Events w/ Field", distinctValues as "Distinct Values", numeric_count as "Numeric Count", values as "Top values with count of each"
```

----------------------------------------------------------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------------------------------------------------------

### Fieldsummary - Groupby `index`

- Uses `| makeresults` to create a multivalue insert list of indexes, passes them to map command.

```spl
|  makeresults 
| fields - _time 
| eval list = "oswin*
osnix*" 
| makemv list tokenizer="([^\n]+)" 
| mvexpand list 
| rename list AS index 
| eval comment = if(1==1, null(), "
START initial fieldsummary command execution.
    Note: Remove any fields desired. Modify 'maxvals' setting to desired number of output values. 'DistinctValues' calculation is up to 5x the maxvals specified.
    Fieldsummary command accepts list of fields as filter. Leave empty for '*' all fields.
") 
| map maxsearches=10 search="search (index=\"$index$\") 
    | fields - \"date_*\", eventtype, host, linecount, punct, \"splunk_server*\", timestartpos, timeendpos, timestamp
    | fieldsummary maxvals=5
    | where (count > 0)
    | eval index = \"$index$\" " 
| eval comment = if(1==1, null(), "
END initial fieldsummary command execution via map.


START fieldsummary transformations and base calculations/filtering.
") 
| eval distinctValues=case(
    (is_exact == 1), (distinct_count . " (Exact)"),
    (is_exact == 0),(distinct_count . " (Estimate)")
    ) 
| eventstats max(count) as eventCount BY index 
| eval diffPerc=(round(((count / eventCount) * 100),1) . "%") 
| eval comment = if(1==1, null(), "
    Note: Modify | where command below based on desired minimum % of events containing a field with values for that field to be displayed.") 
| where (tonumber(rtrim(diffPerc,"%")) > 10) 
| fields - distinct_count, eventCount, is_exact, mean, max, min, stdev
| eval comment = if(1==1, null(), "
END fieldsummary transformations and base calculations/filtering.


START reformatting of 'values' JSON data into readable Multivalue field.
")
| spath input=values path="{}.value" output="value_strings" 
| eval comment = if(1==1, null(), "
    Note: Wrap the value_strings field with doublequotes through multivalue functions without expanding by using ':::' as a delimiter.") 
| eval value_strings = split("\"" . mvjoin(value_strings, "\":::\"") . "\"", ":::") 
| spath input=values path="{}.count" output="value_counts" 
| eval comment = if(1==1, null(), "
    Note: Concat the two into a single MV field, formatted as 'value_strings': value_counts") 
| eval values = mvzip(value_strings, value_counts, ": ") 
| fields - value_counts, value_strings 
| eval comment = if(1==1, null(), "
END reformatting of 'values' JSON data into readable Multivalue field.


START column alignment formatting for values field. 
    Note: column alignment, if calculated on the aggregate dataset without GROUPBY, can result in wrapped lines if the dataset contains any fields with long values.") 
| mvexpand values 
| rex field=values "^(?<fieldValueString>\".+\"):\s(?<fieldValueCount>\d+)" 
| eventstats max(eval(len(fieldValueString))) AS max_fieldValue_len BY field, index 
| eval whitespaceInsertAmount=((max_fieldValue_len + 4) - len(fieldValueString)) 
| eval values = fieldValueString . substr("                                                                                                                                                           ",1,whitespaceInsertAmount) . ":" . fieldValueCount 
| fields - whitespaceInsertAmount, max_fieldValue_len, fieldValueString, fieldValueCount 
| stats list(values) AS values, values(values) AS values_ThisMustBeSeparateToRetainOrdering, values(*) AS * BY field, index 
| fields - values_ThisMustBeSeparateToRetainOrdering
| eval comment = if(1==1, null(), "
END column alignment formatting for values field.


START row deduplication/aggregation of duplicate information across multiple fields into a single row through using a md5 hash. If all the columns EXCEPT field name are equivalent, aggregate.
") 
| eval valuesHash = md5(mvjoin(values, ":::")) 
| eval checkSum = md5( index . ":::" . count . ":::" . diffPerc . ":::" . numeric_count . ":::" . distinctValues . ":::" . valuesHash) 
| eventstats values(field) AS field BY checkSum 
| sort 0 - checkSum 
| streamstats count AS duplicateCount BY checkSum 
| where duplicateCount < 2 
| eval comment = if(1==1, null(), "
END row deduplication/aggregation of duplicate information across multiple fields into a single row through using a md5 hash.
") 
| sort 0 index, -count 
| table index, field, count, diffPerc, numeric_count, distinctValues, values
| rename count as "Count of Events w/ Field", diffPerc as "Perc of Total Events w/ Field", distinctValues as "Distinct Values", numeric_count as "Numeric Count", values as "Top values with count of each"
```



----------------------------------------------------------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------------------------------------------------------

### Fieldsummary - Groupby `index`, `sourcetype`, `source`

- Uses `| tstats` as an input for list of index, sourcetype, source values to pass into map command searches.

```spl
| tstats count WHERE index=* BY index, sourcetype, source
| eval comment = if(1==1, null(), "
START initial fieldsummary command execution.
    Note: Remove any fields desired. Modify 'maxvals' setting to desired number of output values. 'DistinctValues' calculation is up to 5x the maxvals specified.
    Fieldsummary command accepts list of fields as filter. Leave empty for '*' all fields.
") 
| map maxsearches=100 search="search (index=\"$index$\" sourcetype=\"$sourcetype$\" source=\"$source$\")
    | fields - \"date_*\", host, linecount, punct, \"splunk_server*\", timestartpos, timeendpos, timestamp 
    | fieldsummary maxvals=5 
    | where (count > 0)
    | eval index = \"$index$\"
    | eval sourcetype = \"$sourcetype$\"
    | eval source = \"$source$\"
    "
| eval comment = if(1==1, null(), "
END initial fieldsummary command execution via map.


START fieldsummary transformations and base calculations/filtering.
") 
| eval distinctValues=case(
    (is_exact == 1), (distinct_count . " (Exact)"),
    (is_exact == 0),(distinct_count . " (Estimate)")
    ) 
| eventstats max(count) as eventCount BY index, sourcetype, source
| eval diffPerc=(round(((count / eventCount) * 100),1) . "%") 
| eval comment = if(1==1, null(), "
    Note: Modify | where command below based on desired minimum % of events containing a field with values for that field to be displayed.") 
| where (tonumber(rtrim(diffPerc,"%")) > 10) 
| fields - distinct_count, eventCount, is_exact, mean, max, min, stdev
| eval comment = if(1==1, null(), "
END fieldsummary transformations and base calculations/filtering.


START reformatting of 'values' JSON data into readable Multivalue field.
")
| spath input=values path="{}.value" output="value_strings" 
| eval comment = if(1==1, null(), "
    Note: Wrap the value_strings field with doublequotes through multivalue functions without expanding by using ':::' as a delimiter.") 
| eval value_strings = split("\"" . mvjoin(value_strings, "\":::\"") . "\"", ":::") 
| spath input=values path="{}.count" output="value_counts" 
| eval comment = if(1==1, null(), "
    Note: Concat the two into a single MV field, formatted as 'value_strings': value_counts") 
| eval values = mvzip(value_strings, value_counts, ": ") 
| fields - value_counts, value_strings 
| eval comment = if(1==1, null(), "
END reformatting of 'values' JSON data into readable Multivalue field.


START column alignment formatting for values field. 
    Note: column alignment, if calculated on the aggregate dataset without GROUPBY, can result in wrapped lines if the dataset contains any fields with long values.") 
| mvexpand values 
| rex field=values "^(?<fieldValueString>\".+\"):\s(?<fieldValueCount>\d+)" 
| eventstats max(eval(len(fieldValueString))) AS max_fieldValue_len BY field, index, sourcetype, source 
| eval whitespaceInsertAmount=((max_fieldValue_len + 4) - len(fieldValueString)) 
| eval values = fieldValueString . substr("                                                                                                                                                           ",1,whitespaceInsertAmount) . ":" . fieldValueCount 
| fields - whitespaceInsertAmount, max_fieldValue_len, fieldValueString, fieldValueCount 
| stats list(values) AS values, values(values) AS values_ThisMustBeSeparateToRetainOrdering, values(*) AS * BY field, index, sourcetype, source
| fields - values_ThisMustBeSeparateToRetainOrdering
| eval comment = if(1==1, null(), "
END column alignment formatting for values field.


START row deduplication/aggregation of duplicate information across multiple fields into a single row through using a md5 hash. If all the columns EXCEPT field name are equivalent, aggregate.
") 
| eval valuesHash = md5(mvjoin(values, ":::")) 
| eval checkSum = md5( index . ":::" . sourcetype . ":::" . source . ":::" . count . ":::" . diffPerc . ":::" . numeric_count . ":::" . distinctValues . ":::" . valuesHash) 
| eventstats values(field) AS field BY checkSum 
| sort 0 - checkSum 
| streamstats count AS duplicateCount BY checkSum 
| where duplicateCount < 2 
| eval comment = if(1==1, null(), "
END row deduplication/aggregation of duplicate information across multiple fields into a single row through using a md5 hash.
") 
| sort 0 -count 
| table index, sourcetype, source, field, count, diffPerc, numeric_count, distinctValues, values
| rename count as "Count of Events w/ Field", diffPerc as "Perc of Total Events w/ Field", distinctValues as "Distinct Values", numeric_count as "Numeric Count", values as "Top values with count of each"
```
