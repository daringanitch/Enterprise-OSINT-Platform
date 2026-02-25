import React, { useState, useEffect, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import {
  Box,
  Tabs,
  Tab,
  Card,
  CardContent,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  CircularProgress,
  Alert,
  Tooltip,
  Grid,
  Typography,
  Paper,
  IconButton,
  LinearProgress,
  Divider,
} from '@mui/material';
import { alpha, useTheme } from '@mui/material/styles';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Close as CloseIcon,
  Check as CheckIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import { cyberColors, designTokens, glassmorphism } from '../utils/theme';
import { pageVariants } from '../utils/animations';

const ADMIRALTY_SCALE = ['A', 'B', 'C', 'D', 'E', 'F'];
const CREDIBILITY_SCALE = ['1', '2', '3', '4', '5', '6'];
const CONSISTENCY_OPTIONS = ['C', 'I', 'N', 'NA'] as const;
const HYPOTHESIS_TYPES = ['primary', 'alternative', 'devil_advocate', 'null'] as const;
const HYPOTHESIS_STATUSES = ['open', 'confirmed', 'rejected', 'tentative'] as const;
const CONFIDENCE_LEVELS = ['High', 'Moderate', 'Low'];

interface IntelligenceItem {
  id: string;
  title: string;
  content: string;
  source_name: string;
  source_type: 'human' | 'technical' | 'osint' | 'document' | 'signal';
  source_reliability: string;
  info_credibility: string;
  collection_method: string;
  analyst_notes: string;
  created_at: string;
}

interface Hypothesis {
  id: string;
  title: string;
  description: string;
  type: typeof HYPOTHESIS_TYPES[number];
  status: typeof HYPOTHESIS_STATUSES[number];
  rejection_rationale?: string;
  created_at: string;
}

interface ACHCell {
  evidence_id: string;
  hypothesis_id: string;
  consistency: typeof CONSISTENCY_OPTIONS[number] | null;
}

interface Conclusion {
  id: string;
  key_judgement: string;
  confidence_level: 'High' | 'Moderate' | 'Low';
  wep_phrase: string;
  reasoning: string;
  created_at: string;
}

interface AlternativeExplanation {
  id: string;
  alternative_text: string;
  why_considered: string;
  why_rejected: string;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

function AnalyticWorkbench() {
  const theme = useTheme();
  const { id } = useParams<{ id: string }>();
  const [currentTab, setCurrentTab] = useState(0);
  const [loading, setLoading] = useState(false);
  const token = localStorage.getItem('token');

  // Intelligence Items state
  const [items, setItems] = useState<IntelligenceItem[]>([]);
  const [itemDialogOpen, setItemDialogOpen] = useState(false);
  const [selectedItem, setSelectedItem] = useState<IntelligenceItem | null>(null);
  const [itemForm, setItemForm] = useState({
    title: '',
    content: '',
    source_name: '',
    source_type: 'osint' as IntelligenceItem['source_type'],
    source_reliability: 'C',
    info_credibility: '3',
    collection_method: '',
    analyst_notes: '',
  });

  // Hypotheses state
  const [hypotheses, setHypotheses] = useState<Hypothesis[]>([]);
  const [hypDialogOpen, setHypDialogOpen] = useState(false);
  const [selectedHyp, setSelectedHyp] = useState<Hypothesis | null>(null);
  const [hypForm, setHypForm] = useState({
    title: '',
    description: '',
    type: 'primary' as Hypothesis['type'],
    status: 'open' as Hypothesis['status'],
    rejection_rationale: '',
  });

  // ACH Matrix state
  const [achMatrix, setAchMatrix] = useState<ACHCell[]>([]);
  const [achScores, setAchScores] = useState<Record<string, number>>({});

  // Conclusions state
  const [conclusions, setConclusions] = useState<Conclusion[]>([]);
  const [alternatives, setAlternatives] = useState<Record<string, AlternativeExplanation[]>>({});
  const [concDialogOpen, setConcDialogOpen] = useState(false);
  const [selectedConc, setSelectedConc] = useState<Conclusion | null>(null);
  const [concForm, setConcForm] = useState({
    key_judgement: '',
    confidence_level: 'Moderate' as Conclusion['confidence_level'],
    wep_phrase: 'We assess that',
    reasoning: '',
  });
  const [altForm, setAltForm] = useState({
    alternative_text: '',
    why_considered: '',
    why_rejected: '',
  });

  const apiCall = useCallback(
    async (method: string, endpoint: string, body?: unknown) => {
      const url = `${process.env.REACT_APP_API_URL || 'http://localhost:5001'}${endpoint}`;
      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
      if (!response.ok) {
        throw new Error(`API error: ${response.statusText}`);
      }
      return response.json();
    },
    [token]
  );

  // Load all data
  useEffect(() => {
    if (!id) return;
    loadAllData();
  }, [id, apiCall]);

  const loadAllData = async () => {
    setLoading(true);
    try {
      const [itemsRes, hypsRes, achRes, concsRes] = await Promise.all([
        apiCall('GET', `/api/tradecraft/investigations/${id}/items`),
        apiCall('GET', `/api/tradecraft/investigations/${id}/hypotheses`),
        apiCall('GET', `/api/tradecraft/investigations/${id}/ach`),
        apiCall('GET', `/api/tradecraft/investigations/${id}/conclusions`),
      ]);
      setItems(itemsRes.items || []);
      setHypotheses(hypsRes.hypotheses || []);
      setAchMatrix(achRes.matrix || []);
      setConclusions(concsRes.conclusions || []);
    } catch (error) {
      console.error('Error loading data:', error);
    } finally {
      setLoading(false);
    }
  };

  // Intelligence Items handlers
  const handleSaveItem = async () => {
    try {
      if (selectedItem) {
        await apiCall('PUT', `/api/tradecraft/items/${selectedItem.id}`, itemForm);
      } else {
        await apiCall('POST', `/api/tradecraft/investigations/${id}/items`, itemForm);
      }
      loadAllData();
      setItemDialogOpen(false);
      resetItemForm();
    } catch (error) {
      console.error('Error saving item:', error);
    }
  };

  const handleDeleteItem = async (itemId: string) => {
    try {
      await apiCall('DELETE', `/api/tradecraft/items/${itemId}`);
      loadAllData();
    } catch (error) {
      console.error('Error deleting item:', error);
    }
  };

  const resetItemForm = () => {
    setItemForm({
      title: '',
      content: '',
      source_name: '',
      source_type: 'osint',
      source_reliability: 'C',
      info_credibility: '3',
      collection_method: '',
      analyst_notes: '',
    });
    setSelectedItem(null);
  };

  const openItemDialog = (item?: IntelligenceItem) => {
    if (item) {
      setSelectedItem(item);
      setItemForm({
        title: item.title,
        content: item.content,
        source_name: item.source_name,
        source_type: item.source_type,
        source_reliability: item.source_reliability,
        info_credibility: item.info_credibility,
        collection_method: item.collection_method,
        analyst_notes: item.analyst_notes,
      });
    }
    setItemDialogOpen(true);
  };

  // Hypotheses handlers
  const handleSaveHypothesis = async () => {
    try {
      if (selectedHyp) {
        await apiCall('PUT', `/api/tradecraft/hypotheses/${selectedHyp.id}`, hypForm);
      } else {
        await apiCall('POST', `/api/tradecraft/investigations/${id}/hypotheses`, hypForm);
      }
      loadAllData();
      setHypDialogOpen(false);
      resetHypForm();
    } catch (error) {
      console.error('Error saving hypothesis:', error);
    }
  };

  const resetHypForm = () => {
    setHypForm({
      title: '',
      description: '',
      type: 'primary',
      status: 'open',
      rejection_rationale: '',
    });
    setSelectedHyp(null);
  };

  const openHypDialog = (hyp?: Hypothesis) => {
    if (hyp) {
      setSelectedHyp(hyp);
      setHypForm({
        title: hyp.title,
        description: hyp.description,
        type: hyp.type,
        status: hyp.status,
        rejection_rationale: hyp.rejection_rationale || '',
      });
    }
    setHypDialogOpen(true);
  };

  // ACH Matrix handlers
  const handleACHCellChange = async (
    evidenceId: string,
    hypothesisId: string,
    consistency: typeof CONSISTENCY_OPTIONS[number]
  ) => {
    try {
      await apiCall('POST', `/api/tradecraft/ach/cell`, {
        evidence_id: evidenceId,
        hypothesis_id: hypothesisId,
        consistency,
      });
      loadAllData();
    } catch (error) {
      console.error('Error updating ACH cell:', error);
    }
  };

  // Conclusions handlers
  const handleSaveConclusion = async () => {
    try {
      if (selectedConc) {
        await apiCall('PUT', `/api/tradecraft/conclusions/${selectedConc.id}`, concForm);
      } else {
        await apiCall('POST', `/api/tradecraft/investigations/${id}/conclusions`, concForm);
      }
      loadAllData();
      setConcDialogOpen(false);
      resetConcForm();
    } catch (error) {
      console.error('Error saving conclusion:', error);
    }
  };

  const handleAddAlternative = async (concId: string) => {
    try {
      await apiCall('POST', `/api/tradecraft/conclusions/${concId}/alternatives`, altForm);
      loadAllData();
      setAltForm({
        alternative_text: '',
        why_considered: '',
        why_rejected: '',
      });
    } catch (error) {
      console.error('Error adding alternative:', error);
    }
  };

  const resetConcForm = () => {
    setConcForm({
      key_judgement: '',
      confidence_level: 'Moderate',
      wep_phrase: 'We assess that',
      reasoning: '',
    });
    setSelectedConc(null);
  };

  const openConcDialog = (conc?: Conclusion) => {
    if (conc) {
      setSelectedConc(conc);
      setConcForm({
        key_judgement: conc.key_judgement,
        confidence_level: conc.confidence_level,
        wep_phrase: conc.wep_phrase,
        reasoning: conc.reasoning,
      });
    }
    setConcDialogOpen(true);
  };

  const getAdmiraltyCode = (reliability: string, credibility: string) => {
    return `${reliability}${credibility}`;
  };

  const getConsistencyColor = (consistency: typeof CONSISTENCY_OPTIONS[number] | null) => {
    switch (consistency) {
      case 'C':
        return cyberColors.neon.green;
      case 'I':
        return cyberColors.neon.red;
      case 'N':
        return cyberColors.text.secondary;
      case 'NA':
        return cyberColors.dark.steel;
      default:
        return cyberColors.dark.steel;
    }
  };

  const getConfidenceColor = (level: 'High' | 'Moderate' | 'Low') => {
    switch (level) {
      case 'High':
        return cyberColors.neon.green;
      case 'Moderate':
        return cyberColors.neon.orange;
      case 'Low':
        return cyberColors.neon.red;
    }
  };

  const getHypothesisTypeColor = (type: typeof HYPOTHESIS_TYPES[number]) => {
    switch (type) {
      case 'primary':
        return cyberColors.neon.cyan;
      case 'alternative':
        return cyberColors.neon.magenta;
      case 'devil_advocate':
        return cyberColors.neon.orange;
      case 'null':
        return cyberColors.text.secondary;
      default:
        return cyberColors.text.secondary;
    }
  };

  const admiraltyTooltip = (
    <Paper sx={{ p: 1 }}>
      <Typography variant="caption" sx={{ fontWeight: 'bold', display: 'block', mb: 1 }}>
        NATO Reliability (Rows) × Credibility (Cols)
      </Typography>
      <Box sx={{ fontSize: '0.7rem', fontFamily: 'monospace' }}>
        <div>A=Completely reliable, B=Usually reliable, C=Fairly reliable</div>
        <div>D=Not usually reliable, E=Unreliable, F=Cannot be judged</div>
        <div>1=Confirmed, 2=Probably true, 3=Possibly true</div>
        <div>4=Doubtfully true, 5=Improbable, 6=Cannot be judged</div>
      </Box>
    </Paper>
  );

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <CircularProgress sx={{ color: cyberColors.neon.cyan }} />
      </Box>
    );
  }

  return (
    <motion.div variants={pageVariants} initial="initial" animate="animate" exit="exit">
      <Box sx={{ p: 3 }}>
        <Typography
          variant="h4"
          sx={{
            fontFamily: designTokens.typography.fontFamily.display,
            color: cyberColors.neon.cyan,
            mb: 3,
            fontWeight: 700,
          }}
        >
          Analytic Workbench
        </Typography>

        <Card sx={{ ...glassmorphism.card, mb: 2 }}>
          <Tabs
            value={currentTab}
            onChange={(_, newValue) => setCurrentTab(newValue)}
            sx={{
              borderBottom: `1px solid ${alpha(cyberColors.neon.cyan, 0.2)}`,
              '& .MuiTab-root': {
                color: cyberColors.text.secondary,
                '&.Mui-selected': {
                  color: cyberColors.neon.cyan,
                },
              },
              '& .MuiTabs-indicator': {
                backgroundColor: cyberColors.neon.cyan,
              },
            }}
          >
            <Tab label="Intelligence Items" />
            <Tab label="Hypotheses" />
            <Tab label="ACH Matrix" />
            <Tab label="Conclusions" />
          </Tabs>

          {/* Tab 1: Intelligence Items */}
          <TabPanel value={currentTab} index={0}>
            <Box sx={{ mb: 2 }}>
              <Button
                startIcon={<AddIcon />}
                variant="contained"
                sx={{
                  backgroundColor: cyberColors.neon.cyan,
                  color: cyberColors.dark.charcoal,
                  '&:hover': { backgroundColor: alpha(cyberColors.neon.cyan, 0.8) },
                }}
                onClick={() => {
                  resetItemForm();
                  openItemDialog();
                }}
              >
                Add Intelligence Item
              </Button>
            </Box>

            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow sx={{ backgroundColor: alpha(cyberColors.neon.cyan, 0.1) }}>
                    <TableCell sx={{ color: cyberColors.neon.cyan, fontWeight: 'bold' }}>
                      Admiralty Code
                    </TableCell>
                    <TableCell sx={{ color: cyberColors.neon.cyan, fontWeight: 'bold' }}>
                      Source
                    </TableCell>
                    <TableCell sx={{ color: cyberColors.neon.cyan, fontWeight: 'bold' }}>
                      Title
                    </TableCell>
                    <TableCell sx={{ color: cyberColors.neon.cyan, fontWeight: 'bold' }}>
                      Collection Method
                    </TableCell>
                    <TableCell sx={{ color: cyberColors.neon.cyan, fontWeight: 'bold' }}>
                      Actions
                    </TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {items.map((item) => (
                    <TableRow
                      key={item.id}
                      sx={{
                        backgroundColor: alpha(cyberColors.dark.steel, 0.3),
                        '&:hover': {
                          backgroundColor: alpha(cyberColors.neon.cyan, 0.1),
                        },
                      }}
                    >
                      <TableCell>
                        <Tooltip title={admiraltyTooltip}>
                          <Chip
                            label={getAdmiraltyCode(item.source_reliability, item.info_credibility)}
                            sx={{
                              backgroundColor: alpha(cyberColors.neon.cyan, 0.2),
                              color: cyberColors.neon.cyan,
                              fontWeight: 'bold',
                            }}
                          />
                        </Tooltip>
                      </TableCell>
                      <TableCell sx={{ color: cyberColors.text.secondary }}>
                        {item.source_name}
                      </TableCell>
                      <TableCell sx={{ color: cyberColors.text.secondary, maxWidth: '300px' }}>
                        <Typography noWrap variant="body2">
                          {item.title}
                        </Typography>
                      </TableCell>
                      <TableCell sx={{ color: cyberColors.text.secondary }}>
                        {item.collection_method}
                      </TableCell>
                      <TableCell>
                        <IconButton
                          size="small"
                          onClick={() => openItemDialog(item)}
                          sx={{ color: cyberColors.neon.cyan }}
                        >
                          <EditIcon />
                        </IconButton>
                        <IconButton
                          size="small"
                          onClick={() => handleDeleteItem(item.id)}
                          sx={{ color: cyberColors.neon.red }}
                        >
                          <DeleteIcon />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </TabPanel>

          {/* Tab 2: Hypotheses */}
          <TabPanel value={currentTab} index={1}>
            <Box sx={{ mb: 2 }}>
              <Button
                startIcon={<AddIcon />}
                variant="contained"
                sx={{
                  backgroundColor: cyberColors.neon.cyan,
                  color: cyberColors.dark.charcoal,
                  '&:hover': { backgroundColor: alpha(cyberColors.neon.cyan, 0.8) },
                }}
                onClick={() => {
                  resetHypForm();
                  openHypDialog();
                }}
              >
                Add Hypothesis
              </Button>
            </Box>

            <Grid container spacing={2}>
              {hypotheses.map((hyp) => (
                <Grid item xs={12} sm={6} md={4} key={hyp.id}>
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3 }}
                  >
                    <Card
                      sx={{
                        ...glassmorphism.card,
                        border: `1px solid ${alpha(getHypothesisTypeColor(hyp.type), 0.3)}`,
                      }}
                    >
                      <CardContent>
                        <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
                          <Chip
                            label={hyp.type.replace('_', ' ')}
                            size="small"
                            sx={{
                              backgroundColor: alpha(getHypothesisTypeColor(hyp.type), 0.2),
                              color: getHypothesisTypeColor(hyp.type),
                            }}
                          />
                          <Chip
                            label={hyp.status}
                            size="small"
                            sx={{
                              backgroundColor: alpha(cyberColors.neon.cyan, 0.2),
                              color: cyberColors.neon.cyan,
                            }}
                          />
                        </Box>
                        <Typography
                          variant="h6"
                          sx={{
                            color: cyberColors.neon.cyan,
                            mb: 1,
                            fontFamily: designTokens.typography.fontFamily.display,
                          }}
                        >
                          {hyp.title}
                        </Typography>
                        <Typography
                          variant="body2"
                          sx={{ color: cyberColors.text.secondary, mb: 2 }}
                        >
                          {hyp.description}
                        </Typography>
                        {hyp.status === 'rejected' && hyp.rejection_rationale && (
                          <Alert severity="warning" sx={{ mb: 2 }}>
                            <Typography variant="caption">
                              <strong>Rejection Rationale:</strong> {hyp.rejection_rationale}
                            </Typography>
                          </Alert>
                        )}
                        <Box sx={{ display: 'flex', gap: 1 }}>
                          <Button
                            size="small"
                            startIcon={<EditIcon />}
                            onClick={() => openHypDialog(hyp)}
                            sx={{ color: cyberColors.neon.cyan }}
                          >
                            Edit
                          </Button>
                        </Box>
                      </CardContent>
                    </Card>
                  </motion.div>
                </Grid>
              ))}
            </Grid>
          </TabPanel>

          {/* Tab 3: ACH Matrix */}
          <TabPanel value={currentTab} index={2}>
            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="body2">
                <strong>ACH Legend:</strong> C=Consistent (green), I=Inconsistent (red), N=Not
                applicable (gray), NA=Not assessed (muted)
              </Typography>
            </Alert>

            {items.length === 0 || hypotheses.length === 0 ? (
              <Alert severity="warning">
                Add intelligence items and hypotheses to display the ACH matrix.
              </Alert>
            ) : (
              <TableContainer sx={{ overflowX: 'auto' }}>
                <Table>
                  <TableHead>
                    <TableRow sx={{ backgroundColor: alpha(cyberColors.neon.cyan, 0.1) }}>
                      <TableCell sx={{ color: cyberColors.neon.cyan, fontWeight: 'bold' }}>
                        Evidence
                      </TableCell>
                      {hypotheses.map((hyp) => (
                        <TableCell
                          key={hyp.id}
                          sx={{ color: cyberColors.neon.cyan, fontWeight: 'bold', minWidth: 150 }}
                        >
                          <Typography variant="caption">{hyp.title}</Typography>
                        </TableCell>
                      ))}
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {items.map((item) => (
                      <TableRow key={item.id}>
                        <TableCell sx={{ color: cyberColors.text.secondary, fontWeight: 'bold' }}>
                          <Typography variant="caption" noWrap sx={{ maxWidth: 150 }}>
                            {item.title}
                          </Typography>
                        </TableCell>
                        {hypotheses.map((hyp) => {
                          const cellData = achMatrix.find(
                            (c) => c.evidence_id === item.id && c.hypothesis_id === hyp.id
                          );
                          return (
                            <TableCell key={`${item.id}-${hyp.id}`}>
                              <Box sx={{ display: 'flex', gap: 0.5 }}>
                                {CONSISTENCY_OPTIONS.map((option) => (
                                  <Tooltip key={option} title={option}>
                                    <Button
                                      size="small"
                                      variant={cellData?.consistency === option ? 'contained' : 'outlined'}
                                      sx={{
                                        minWidth: '32px',
                                        backgroundColor:
                                          cellData?.consistency === option
                                            ? getConsistencyColor(option)
                                            : 'transparent',
                                        color:
                                          cellData?.consistency === option
                                            ? cyberColors.dark.charcoal
                                            : getConsistencyColor(option),
                                        borderColor: getConsistencyColor(option),
                                        '&:hover': {
                                          backgroundColor: alpha(getConsistencyColor(option), 0.2),
                                        },
                                      }}
                                      onClick={() =>
                                        handleACHCellChange(item.id, hyp.id, option)
                                      }
                                    >
                                      {option}
                                    </Button>
                                  </Tooltip>
                                ))}
                              </Box>
                            </TableCell>
                          );
                        })}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </TabPanel>

          {/* Tab 4: Conclusions */}
          <TabPanel value={currentTab} index={3}>
            <Box sx={{ mb: 2 }}>
              <Button
                startIcon={<AddIcon />}
                variant="contained"
                sx={{
                  backgroundColor: cyberColors.neon.cyan,
                  color: cyberColors.dark.charcoal,
                  '&:hover': { backgroundColor: alpha(cyberColors.neon.cyan, 0.8) },
                }}
                onClick={() => {
                  resetConcForm();
                  openConcDialog();
                }}
              >
                Add Conclusion
              </Button>
            </Box>

            <Grid container spacing={2}>
              {conclusions.map((conc) => (
                <Grid item xs={12} key={conc.id}>
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3 }}
                  >
                    <Card
                      sx={{
                        ...glassmorphism.card,
                        border: `1px solid ${alpha(getConfidenceColor(conc.confidence_level), 0.3)}`,
                      }}
                    >
                      <CardContent>
                        <Box sx={{ display: 'flex', gap: 2, mb: 2, alignItems: 'center' }}>
                          <Chip
                            label={conc.confidence_level}
                            sx={{
                              backgroundColor: alpha(
                                getConfidenceColor(conc.confidence_level),
                                0.2
                              ),
                              color: getConfidenceColor(conc.confidence_level),
                              fontWeight: 'bold',
                            }}
                          />
                          <Typography
                            variant="body2"
                            sx={{
                              color: cyberColors.text.secondary,
                              fontStyle: 'italic',
                            }}
                          >
                            {conc.wep_phrase}
                          </Typography>
                        </Box>

                        <Typography
                          variant="h6"
                          sx={{
                            color: cyberColors.neon.cyan,
                            mb: 2,
                            fontFamily: designTokens.typography.fontFamily.display,
                          }}
                        >
                          {conc.key_judgement}
                        </Typography>

                        <Box
                          sx={{
                            backgroundColor: alpha(cyberColors.neon.cyan, 0.1),
                            p: 2,
                            borderRadius: 1,
                            mb: 2,
                          }}
                        >
                          <Typography
                            variant="body2"
                            sx={{
                              color: cyberColors.text.secondary,
                              fontStyle: 'italic',
                            }}
                          >
                            <strong>IC Statement:</strong> {conc.wep_phrase} with{' '}
                            {conc.confidence_level.toLowerCase()} confidence that{' '}
                            {conc.key_judgement}.
                          </Typography>
                        </Box>

                        <Divider sx={{ my: 2, borderColor: alpha(cyberColors.neon.cyan, 0.2) }} />

                        <Typography
                          variant="subtitle2"
                          sx={{ color: cyberColors.neon.cyan, mb: 1, fontWeight: 'bold' }}
                        >
                          Alternative Explanations
                        </Typography>
                        {(!alternatives[conc.id] || alternatives[conc.id].length === 0) && (
                          <Alert
                            severity="warning"
                            icon={<WarningIcon />}
                            sx={{ mb: 2, fontSize: '0.875rem' }}
                          >
                            No alternative explanations added. This is required.
                          </Alert>
                        )}
                        <Box sx={{ mb: 2 }}>
                          {alternatives[conc.id]?.map((alt) => (
                            <Box
                              key={alt.id}
                              sx={{
                                backgroundColor: alpha(cyberColors.neon.magenta, 0.1),
                                p: 1.5,
                                borderRadius: 1,
                                mb: 1,
                              }}
                            >
                              <Typography variant="body2" sx={{ color: cyberColors.text.secondary }}>
                                <strong>Alternative:</strong> {alt.alternative_text}
                              </Typography>
                              <Typography
                                variant="caption"
                                sx={{ color: cyberColors.text.secondary, display: 'block' }}
                              >
                                <strong>Why considered:</strong> {alt.why_considered}
                              </Typography>
                              <Typography
                                variant="caption"
                                sx={{ color: cyberColors.text.secondary }}
                              >
                                <strong>Why rejected:</strong> {alt.why_rejected}
                              </Typography>
                            </Box>
                          ))}
                        </Box>

                        <Box sx={{ display: 'flex', gap: 1 }}>
                          <Button
                            size="small"
                            startIcon={<EditIcon />}
                            onClick={() => openConcDialog(conc)}
                            sx={{ color: cyberColors.neon.cyan }}
                          >
                            Edit
                          </Button>
                        </Box>
                      </CardContent>
                    </Card>
                  </motion.div>
                </Grid>
              ))}
            </Grid>
          </TabPanel>
        </Card>
      </Box>

      {/* Intelligence Item Dialog */}
      <Dialog open={itemDialogOpen} onClose={() => setItemDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ color: cyberColors.neon.cyan, fontWeight: 'bold' }}>
          {selectedItem ? 'Edit Intelligence Item' : 'Add Intelligence Item'}
        </DialogTitle>
        <DialogContent sx={{ pt: 2 }}>
          <TextField
            fullWidth
            label="Title"
            value={itemForm.title}
            onChange={(e) => setItemForm({ ...itemForm, title: e.target.value })}
            margin="normal"
            sx={{
              '& .MuiOutlinedInput-root': {
                color: cyberColors.text.secondary,
              },
            }}
          />
          <TextField
            fullWidth
            label="Content"
            value={itemForm.content}
            onChange={(e) => setItemForm({ ...itemForm, content: e.target.value })}
            margin="normal"
            multiline
            rows={3}
            sx={{
              '& .MuiOutlinedInput-root': {
                color: cyberColors.text.secondary,
              },
            }}
          />
          <TextField
            fullWidth
            label="Source Name"
            value={itemForm.source_name}
            onChange={(e) => setItemForm({ ...itemForm, source_name: e.target.value })}
            margin="normal"
            sx={{
              '& .MuiOutlinedInput-root': {
                color: cyberColors.text.secondary,
              },
            }}
          />
          <FormControl fullWidth margin="normal">
            <InputLabel>Source Type</InputLabel>
            <Select
              value={itemForm.source_type}
              onChange={(e) =>
                setItemForm({ ...itemForm, source_type: e.target.value as typeof itemForm.source_type })
              }
              label="Source Type"
              sx={{
                color: cyberColors.text.secondary,
              }}
            >
              <MenuItem value="human">Human Intelligence</MenuItem>
              <MenuItem value="technical">Technical Intelligence</MenuItem>
              <MenuItem value="osint">Open Source</MenuItem>
              <MenuItem value="document">Document</MenuItem>
              <MenuItem value="signal">Signal Intelligence</MenuItem>
            </Select>
          </FormControl>
          <FormControl fullWidth margin="normal">
            <InputLabel>Source Reliability</InputLabel>
            <Select
              value={itemForm.source_reliability}
              onChange={(e) =>
                setItemForm({ ...itemForm, source_reliability: e.target.value })
              }
              label="Source Reliability"
              sx={{
                color: cyberColors.text.secondary,
              }}
            >
              <MenuItem value="A">A - Completely Reliable</MenuItem>
              <MenuItem value="B">B - Usually Reliable</MenuItem>
              <MenuItem value="C">C - Fairly Reliable</MenuItem>
              <MenuItem value="D">D - Not Usually Reliable</MenuItem>
              <MenuItem value="E">E - Unreliable</MenuItem>
              <MenuItem value="F">F - Cannot Be Judged</MenuItem>
            </Select>
          </FormControl>
          <FormControl fullWidth margin="normal">
            <InputLabel>Information Credibility</InputLabel>
            <Select
              value={itemForm.info_credibility}
              onChange={(e) =>
                setItemForm({ ...itemForm, info_credibility: e.target.value })
              }
              label="Information Credibility"
              sx={{
                color: cyberColors.text.secondary,
              }}
            >
              <MenuItem value="1">1 - Confirmed by Other Sources</MenuItem>
              <MenuItem value="2">2 - Probably True</MenuItem>
              <MenuItem value="3">3 - Possibly True</MenuItem>
              <MenuItem value="4">4 - Doubtfully True</MenuItem>
              <MenuItem value="5">5 - Improbable</MenuItem>
              <MenuItem value="6">6 - Cannot Be Judged</MenuItem>
            </Select>
          </FormControl>
          <TextField
            fullWidth
            label="Collection Method"
            value={itemForm.collection_method}
            onChange={(e) => setItemForm({ ...itemForm, collection_method: e.target.value })}
            margin="normal"
            sx={{
              '& .MuiOutlinedInput-root': {
                color: cyberColors.text.secondary,
              },
            }}
          />
          <TextField
            fullWidth
            label="Analyst Notes"
            value={itemForm.analyst_notes}
            onChange={(e) => setItemForm({ ...itemForm, analyst_notes: e.target.value })}
            margin="normal"
            multiline
            rows={2}
            sx={{
              '& .MuiOutlinedInput-root': {
                color: cyberColors.text.secondary,
              },
            }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setItemDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleSaveItem} variant="contained" sx={{ backgroundColor: cyberColors.neon.cyan }}>
            Save
          </Button>
        </DialogActions>
      </Dialog>

      {/* Hypothesis Dialog */}
      <Dialog open={hypDialogOpen} onClose={() => setHypDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ color: cyberColors.neon.cyan, fontWeight: 'bold' }}>
          {selectedHyp ? 'Edit Hypothesis' : 'Add Hypothesis'}
        </DialogTitle>
        <DialogContent sx={{ pt: 2 }}>
          <TextField
            fullWidth
            label="Title"
            value={hypForm.title}
            onChange={(e) => setHypForm({ ...hypForm, title: e.target.value })}
            margin="normal"
            sx={{
              '& .MuiOutlinedInput-root': {
                color: cyberColors.text.secondary,
              },
            }}
          />
          <TextField
            fullWidth
            label="Description"
            value={hypForm.description}
            onChange={(e) => setHypForm({ ...hypForm, description: e.target.value })}
            margin="normal"
            multiline
            rows={3}
            sx={{
              '& .MuiOutlinedInput-root': {
                color: cyberColors.text.secondary,
              },
            }}
          />
          <FormControl fullWidth margin="normal">
            <InputLabel>Type</InputLabel>
            <Select
              value={hypForm.type}
              onChange={(e) => setHypForm({ ...hypForm, type: e.target.value as typeof hypForm.type })}
              label="Type"
              sx={{
                color: cyberColors.text.secondary,
              }}
            >
              <MenuItem value="primary">Primary</MenuItem>
              <MenuItem value="alternative">Alternative</MenuItem>
              <MenuItem value="devil_advocate">Devil's Advocate</MenuItem>
              <MenuItem value="null">Null Hypothesis</MenuItem>
            </Select>
          </FormControl>
          <FormControl fullWidth margin="normal">
            <InputLabel>Status</InputLabel>
            <Select
              value={hypForm.status}
              onChange={(e) => setHypForm({ ...hypForm, status: e.target.value as typeof hypForm.status })}
              label="Status"
              sx={{
                color: cyberColors.text.secondary,
              }}
            >
              <MenuItem value="open">Open</MenuItem>
              <MenuItem value="confirmed">Confirmed</MenuItem>
              <MenuItem value="rejected">Rejected</MenuItem>
              <MenuItem value="tentative">Tentative</MenuItem>
            </Select>
          </FormControl>
          {(hypForm.status as string) === 'rejected' && (
            <TextField
              fullWidth
              label="Rejection Rationale"
              value={hypForm.rejection_rationale}
              onChange={(e) => setHypForm({ ...hypForm, rejection_rationale: e.target.value })}
              margin="normal"
              multiline
              rows={2}
              sx={{
                '& .MuiOutlinedInput-root': {
                  color: cyberColors.text.secondary,
                },
              }}
            />
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setHypDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleSaveHypothesis} variant="contained" sx={{ backgroundColor: cyberColors.neon.cyan }}>
            Save
          </Button>
        </DialogActions>
      </Dialog>

      {/* Conclusion Dialog */}
      <Dialog open={concDialogOpen} onClose={() => setConcDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ color: cyberColors.neon.cyan, fontWeight: 'bold' }}>
          {selectedConc ? 'Edit Conclusion' : 'Add Conclusion'}
        </DialogTitle>
        <DialogContent sx={{ pt: 2 }}>
          <TextField
            fullWidth
            label="Key Judgement"
            value={concForm.key_judgement}
            onChange={(e) => setConcForm({ ...concForm, key_judgement: e.target.value })}
            margin="normal"
            multiline
            rows={3}
            sx={{
              '& .MuiOutlinedInput-root': {
                color: cyberColors.text.secondary,
              },
            }}
          />
          <FormControl fullWidth margin="normal">
            <InputLabel>Confidence Level</InputLabel>
            <Select
              value={concForm.confidence_level}
              onChange={(e) =>
                setConcForm({
                  ...concForm,
                  confidence_level: e.target.value as typeof concForm.confidence_level,
                })
              }
              label="Confidence Level"
              sx={{
                color: cyberColors.text.secondary,
              }}
            >
              <MenuItem value="High">High</MenuItem>
              <MenuItem value="Moderate">Moderate</MenuItem>
              <MenuItem value="Low">Low</MenuItem>
            </Select>
          </FormControl>
          <TextField
            fullWidth
            label="WEP Phrase"
            value={concForm.wep_phrase}
            onChange={(e) => setConcForm({ ...concForm, wep_phrase: e.target.value })}
            margin="normal"
            placeholder="e.g., We assess that..."
            sx={{
              '& .MuiOutlinedInput-root': {
                color: cyberColors.text.secondary,
              },
            }}
          />
          <TextField
            fullWidth
            label="Reasoning"
            value={concForm.reasoning}
            onChange={(e) => setConcForm({ ...concForm, reasoning: e.target.value })}
            margin="normal"
            multiline
            rows={3}
            sx={{
              '& .MuiOutlinedInput-root': {
                color: cyberColors.text.secondary,
              },
            }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConcDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleSaveConclusion} variant="contained" sx={{ backgroundColor: cyberColors.neon.cyan }}>
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </motion.div>
  );
}

export default AnalyticWorkbench;
