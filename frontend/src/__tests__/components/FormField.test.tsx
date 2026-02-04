/**
 * FormField Component Tests
 */

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { theme } from '../../utils/theme';
import {
  TextInput,
  SelectInput,
  CheckboxInput,
  SwitchInput,
  Textarea,
} from '../../components/common/FormField';

// Mock ResizeObserver for MUI TextareaAutosize
class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
window.ResizeObserver = ResizeObserver;

const renderWithTheme = (component: React.ReactElement) => {
  return render(<ThemeProvider theme={theme}>{component}</ThemeProvider>);
};

describe('TextInput Component', () => {
  describe('Rendering', () => {
    it('renders with label', () => {
      renderWithTheme(<TextInput label="Username" />);
      expect(screen.getByLabelText('Username')).toBeInTheDocument();
    });

    it('renders with testId', () => {
      renderWithTheme(<TextInput label="Email" testId="email-input" />);
      expect(screen.getByTestId('email-input')).toBeInTheDocument();
    });

    it('renders with placeholder', () => {
      renderWithTheme(<TextInput label="Search" placeholder="Type to search..." />);
      expect(screen.getByPlaceholderText('Type to search...')).toBeInTheDocument();
    });

    it('renders with helper text', () => {
      renderWithTheme(<TextInput label="Password" helperText="Must be 8+ characters" />);
      expect(screen.getByText('Must be 8+ characters')).toBeInTheDocument();
    });
  });

  describe('States', () => {
    it('shows error state', () => {
      renderWithTheme(
        <TextInput label="Email" error helperText="Invalid email" />
      );
      expect(screen.getByText('Invalid email')).toBeInTheDocument();
    });

    it('handles disabled state', () => {
      renderWithTheme(<TextInput label="Disabled" disabled />);
      expect(screen.getByLabelText('Disabled')).toBeDisabled();
    });

    it('handles required state', () => {
      renderWithTheme(<TextInput label="Required Field" required />);
      expect(screen.getByLabelText(/required field/i)).toBeRequired();
    });
  });

  describe('Icons', () => {
    it('renders with start icon', () => {
      renderWithTheme(
        <TextInput label="Search" startIcon={<span data-testid="search-icon">🔍</span>} />
      );
      expect(screen.getByTestId('search-icon')).toBeInTheDocument();
    });

    it('renders with end icon', () => {
      renderWithTheme(
        <TextInput label="Password" endIcon={<span data-testid="eye-icon">👁</span>} />
      );
      expect(screen.getByTestId('eye-icon')).toBeInTheDocument();
    });
  });

  describe('Interactions', () => {
    it('handles value changes', () => {
      const handleChange = jest.fn();
      renderWithTheme(<TextInput label="Name" onChange={handleChange} />);
      fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'John' } });
      expect(handleChange).toHaveBeenCalled();
    });
  });
});

describe('SelectInput Component', () => {
  const options = [
    { value: 'opt1', label: 'Option 1' },
    { value: 'opt2', label: 'Option 2' },
    { value: 'opt3', label: 'Option 3', disabled: true },
  ];

  describe('Rendering', () => {
    it('renders with label', () => {
      renderWithTheme(
        <SelectInput label="Select Option" value="" onChange={() => {}} options={options} />
      );
      expect(screen.getByLabelText('Select Option')).toBeInTheDocument();
    });

    it('renders with testId', () => {
      renderWithTheme(
        <SelectInput
          label="Type"
          value=""
          onChange={() => {}}
          options={options}
          testId="type-select"
        />
      );
      expect(screen.getByTestId('type-select')).toBeInTheDocument();
    });

    it('renders with helper text', () => {
      renderWithTheme(
        <SelectInput
          label="Category"
          value=""
          onChange={() => {}}
          options={options}
          helperText="Choose a category"
        />
      );
      expect(screen.getByText('Choose a category')).toBeInTheDocument();
    });
  });

  describe('States', () => {
    it('shows error state', () => {
      renderWithTheme(
        <SelectInput
          label="Required"
          value=""
          onChange={() => {}}
          options={options}
          error
          helperText="This field is required"
        />
      );
      expect(screen.getByText('This field is required')).toBeInTheDocument();
    });

    it('handles disabled state', () => {
      renderWithTheme(
        <SelectInput
          label="Disabled"
          value=""
          onChange={() => {}}
          options={options}
          disabled
        />
      );
      // MUI Select disabled is handled differently
      expect(screen.getByLabelText('Disabled')).toHaveAttribute('aria-disabled', 'true');
    });
  });

  describe('Interactions', () => {
    it('calls onChange with selected value', () => {
      const handleChange = jest.fn();
      renderWithTheme(
        <SelectInput
          label="Options"
          value=""
          onChange={handleChange}
          options={options}
          testId="select-input"
        />
      );

      // Open dropdown
      fireEvent.mouseDown(screen.getByLabelText('Options'));

      // Select option
      fireEvent.click(screen.getByText('Option 1'));
      expect(handleChange).toHaveBeenCalledWith('opt1');
    });
  });

  describe('Placeholder', () => {
    it('renders with placeholder', () => {
      renderWithTheme(
        <SelectInput
          label="Choose"
          value=""
          onChange={() => {}}
          options={options}
          placeholder="Select an option"
        />
      );
      // Placeholder is shown when value is empty
      fireEvent.mouseDown(screen.getByLabelText('Choose'));
      // Multiple placeholder elements may exist (in select and dropdown)
      const placeholders = screen.getAllByText('Select an option');
      expect(placeholders.length).toBeGreaterThan(0);
    });
  });
});

describe('CheckboxInput Component', () => {
  describe('Rendering', () => {
    it('renders with label', () => {
      renderWithTheme(
        <CheckboxInput label="Accept terms" checked={false} onChange={() => {}} />
      );
      expect(screen.getByLabelText('Accept terms')).toBeInTheDocument();
    });

    it('renders with testId', () => {
      renderWithTheme(
        <CheckboxInput
          label="Terms"
          checked={false}
          onChange={() => {}}
          testId="terms-checkbox"
        />
      );
      expect(screen.getByTestId('terms-checkbox')).toBeInTheDocument();
    });

    it('renders with helper text', () => {
      renderWithTheme(
        <CheckboxInput
          label="Subscribe"
          checked={false}
          onChange={() => {}}
          helperText="You can unsubscribe anytime"
        />
      );
      expect(screen.getByText('You can unsubscribe anytime')).toBeInTheDocument();
    });
  });

  describe('States', () => {
    it('shows checked state', () => {
      renderWithTheme(
        <CheckboxInput label="Checked" checked={true} onChange={() => {}} />
      );
      expect(screen.getByRole('checkbox')).toBeChecked();
    });

    it('shows unchecked state', () => {
      renderWithTheme(
        <CheckboxInput label="Unchecked" checked={false} onChange={() => {}} />
      );
      expect(screen.getByRole('checkbox')).not.toBeChecked();
    });

    it('handles disabled state', () => {
      renderWithTheme(
        <CheckboxInput label="Disabled" checked={false} onChange={() => {}} disabled />
      );
      expect(screen.getByRole('checkbox')).toBeDisabled();
    });

    it('handles indeterminate state', () => {
      renderWithTheme(
        <CheckboxInput label="Partial" checked={false} onChange={() => {}} indeterminate />
      );
      expect(screen.getByRole('checkbox')).toHaveAttribute('data-indeterminate', 'true');
    });
  });

  describe('Interactions', () => {
    it('calls onChange when clicked', () => {
      const handleChange = jest.fn();
      renderWithTheme(
        <CheckboxInput label="Toggle" checked={false} onChange={handleChange} />
      );
      fireEvent.click(screen.getByRole('checkbox'));
      expect(handleChange).toHaveBeenCalledWith(true);
    });
  });
});

describe('SwitchInput Component', () => {
  describe('Rendering', () => {
    it('renders with label', () => {
      renderWithTheme(
        <SwitchInput label="Enable feature" checked={false} onChange={() => {}} />
      );
      expect(screen.getByLabelText('Enable feature')).toBeInTheDocument();
    });

    it('renders with testId', () => {
      renderWithTheme(
        <SwitchInput
          label="Feature"
          checked={false}
          onChange={() => {}}
          testId="feature-switch"
        />
      );
      expect(screen.getByTestId('feature-switch')).toBeInTheDocument();
    });

    it('renders with helper text', () => {
      renderWithTheme(
        <SwitchInput
          label="Dark mode"
          checked={false}
          onChange={() => {}}
          helperText="Toggle dark theme"
        />
      );
      expect(screen.getByText('Toggle dark theme')).toBeInTheDocument();
    });
  });

  describe('States', () => {
    it('shows checked state', () => {
      renderWithTheme(
        <SwitchInput label="On" checked={true} onChange={() => {}} />
      );
      expect(screen.getByRole('checkbox')).toBeChecked();
    });

    it('shows unchecked state', () => {
      renderWithTheme(
        <SwitchInput label="Off" checked={false} onChange={() => {}} />
      );
      expect(screen.getByRole('checkbox')).not.toBeChecked();
    });

    it('handles disabled state', () => {
      renderWithTheme(
        <SwitchInput label="Disabled" checked={false} onChange={() => {}} disabled />
      );
      expect(screen.getByRole('checkbox')).toBeDisabled();
    });
  });

  describe('Label Placement', () => {
    const placements = ['start', 'end', 'top', 'bottom'] as const;

    placements.forEach((placement) => {
      it(`renders with ${placement} label placement`, () => {
        renderWithTheme(
          <SwitchInput
            label="Label"
            checked={false}
            onChange={() => {}}
            labelPlacement={placement}
          />
        );
        expect(screen.getByLabelText('Label')).toBeInTheDocument();
      });
    });
  });

  describe('Interactions', () => {
    it('calls onChange when toggled', () => {
      const handleChange = jest.fn();
      renderWithTheme(
        <SwitchInput label="Toggle" checked={false} onChange={handleChange} />
      );
      fireEvent.click(screen.getByRole('checkbox'));
      expect(handleChange).toHaveBeenCalledWith(true);
    });
  });
});

describe('Textarea Component', () => {
  describe('Rendering', () => {
    it('renders with label', () => {
      renderWithTheme(<Textarea label="Description" />);
      expect(screen.getByLabelText('Description')).toBeInTheDocument();
    });

    it('renders with testId', () => {
      renderWithTheme(<Textarea label="Notes" testId="notes-textarea" />);
      expect(screen.getByTestId('notes-textarea')).toBeInTheDocument();
    });

    it('renders with helper text', () => {
      renderWithTheme(
        <Textarea label="Bio" helperText="Max 500 characters" />
      );
      expect(screen.getByText('Max 500 characters')).toBeInTheDocument();
    });
  });

  describe('States', () => {
    it('shows error state', () => {
      renderWithTheme(
        <Textarea label="Comment" error helperText="Comment is too short" />
      );
      expect(screen.getByText('Comment is too short')).toBeInTheDocument();
    });

    it('handles disabled state', () => {
      renderWithTheme(<Textarea label="Disabled" disabled />);
      expect(screen.getByLabelText('Disabled')).toBeDisabled();
    });
  });

  describe('Rows', () => {
    it('renders with fixed rows', () => {
      renderWithTheme(<Textarea label="Fixed" rows={5} />);
      expect(screen.getByLabelText('Fixed')).toHaveAttribute('rows', '5');
    });
  });

  describe('Interactions', () => {
    it('handles value changes', () => {
      const handleChange = jest.fn();
      renderWithTheme(<Textarea label="Content" onChange={handleChange} />);
      fireEvent.change(screen.getByLabelText('Content'), {
        target: { value: 'New content' },
      });
      expect(handleChange).toHaveBeenCalled();
    });
  });
});
